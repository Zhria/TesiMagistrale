package xfrm

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
)

type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}

type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	case message.AUTH_HMAC_SHA2_256_128:
		return "hmac(sha256)"
	default:
		return ""
	}
}

func ApplyXFRMRule(n3iwf_is_initiator bool, xfrmiId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation,
) error {
	return applyXFRMRule(n3iwf_is_initiator, xfrmiId, childSecurityAssociation, nil, nil)
}

// ApplyXFRMRuleWithReplay installs XFRM state/policy rules while preserving ESP
// sequence/anti-replay state. This is required for "no rekey" handover where
// SAs are migrated to a different N3IWF (or reinstated after MOBIKE address update).
func ApplyXFRMRuleWithReplay(
	n3iwf_is_initiator bool,
	xfrmiId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation,
	inboundReplay, outboundReplay *ReplayState,
) error {
	return applyXFRMRule(n3iwf_is_initiator, xfrmiId, childSecurityAssociation, inboundReplay, outboundReplay)
}

func applyXFRMRule(
	n3iwf_is_initiator bool,
	xfrmiId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation,
	inboundReplay, outboundReplay *ReplayState,
) error {
	ikeLog := logger.IKELog
	if childSecurityAssociation == nil {
		return errors.New("nil child security association")
	}

	// Build XFRM information data structure for incoming traffic.

	// Direction: {private_network} -> this_server
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if n3iwf_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name:        XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:         childSecurityAssociation.ResponderToInitiatorIntegrityKey,
				TruncateLen: getTruncateLength(childSecurityAssociation.IntegKInfo.TransformID()),
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name:        XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:         childSecurityAssociation.InitiatorToResponderIntegrityKey,
				TruncateLen: getTruncateLength(childSecurityAssociation.IntegKInfo.TransformID()),
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Ifid = int(xfrmiId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.EsnInfo.GetNeedESN()
	if inboundReplay != nil && inboundReplay.ReplayWindow != 0 {
		xfrmState.ReplayWindow = int(inboundReplay.ReplayWindow) // #nosec G115
	}

	ikeLog.WithFields(logrus.Fields{
		"ifid":          xfrmiId,
		"dir":           "in",
		"inboundSpi":    fmt.Sprintf("0x%08x", childSecurityAssociation.InboundSPI),
		"outboundSpi":   fmt.Sprintf("0x%08x", childSecurityAssociation.OutboundSPI),
		"outerSrc":      ipString(xfrmState.Src),
		"outerDst":      ipString(xfrmState.Dst),
		"tsLocal":       childSecurityAssociation.TrafficSelectorLocal.String(),
		"tsRemote":      childSecurityAssociation.TrafficSelectorRemote.String(),
		"proto":         int(childSecurityAssociation.SelectedIPProtocol),
		"encapEnabled":  childSecurityAssociation.EnableEncapsulate,
		"n3iwfPort":     childSecurityAssociation.N3IWFPort,
		"natPort":       childSecurityAssociation.NATPort,
		"esn":           childSecurityAssociation.EsnInfo.GetNeedESN(),
		"encrAlgo":      xfrmEncryptionAlgorithm.Name,
		"encrKeyFp":     keyFingerprint(xfrmEncryptionAlgorithm.Key),
		"encrKeyLen":    len(xfrmEncryptionAlgorithm.Key),
		"integAlgo":     algoNameOrEmpty(xfrmIntegrityAlgorithm),
		"integKeyFp":    keyFingerprint(keyOrNil(xfrmIntegrityAlgorithm)),
		"integKeyLen":   keyLenOrZero(xfrmIntegrityAlgorithm),
		"integTruncLen": truncLenOrZero(xfrmIntegrityAlgorithm),
	}).Trace("XFRM: applying inbound state/policy")

	// Commit xfrm state to netlink
	var err error
	if inboundReplay != nil {
		err = xfrmStateAddOrUpdateWithReplay(xfrmState, inboundReplay)
	} else {
		err = xfrmStateAddOrUpdate(xfrmState)
	}
	if err != nil {
		return errors.Wrapf(err, "Add XFRM state")
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(xfrmiId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = xfrmPolicyAddOrUpdate(xfrmPolicy); err != nil {
		return errors.Wrapf(err, "Add XFRM policy")
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)

	// Direction: this_server -> {private_network}
	// State
	if n3iwf_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)
	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src

	if childSecurityAssociation.EnableEncapsulate {
		xfrmState.Encap = &netlink.XfrmStateEncap{
			Type:            netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort:         childSecurityAssociation.NATPort,
			DstPort:         childSecurityAssociation.N3IWFPort,
			OriginalAddress: childSecurityAssociation.PeerPublicIPAddr,
		}
	}

	if xfrmState.Encap != nil {
		xfrmState.Encap.SrcPort, xfrmState.Encap.DstPort = xfrmState.Encap.DstPort, xfrmState.Encap.SrcPort
	}
	if outboundReplay != nil && outboundReplay.ReplayWindow != 0 {
		xfrmState.ReplayWindow = int(outboundReplay.ReplayWindow) // #nosec G115
	}

	ikeLog.WithFields(logrus.Fields{
		"ifid":          xfrmiId,
		"dir":           "out",
		"inboundSpi":    fmt.Sprintf("0x%08x", childSecurityAssociation.InboundSPI),
		"outboundSpi":   fmt.Sprintf("0x%08x", childSecurityAssociation.OutboundSPI),
		"outerSrc":      ipString(xfrmState.Src),
		"outerDst":      ipString(xfrmState.Dst),
		"tsLocal":       childSecurityAssociation.TrafficSelectorLocal.String(),
		"tsRemote":      childSecurityAssociation.TrafficSelectorRemote.String(),
		"proto":         int(childSecurityAssociation.SelectedIPProtocol),
		"encapEnabled":  childSecurityAssociation.EnableEncapsulate,
		"encapType":     encapTypeString(xfrmState.Encap),
		"encapSrcPort":  encapPortSrc(xfrmState.Encap),
		"encapDstPort":  encapPortDst(xfrmState.Encap),
		"encapOrigAddr": encapOrigAddr(xfrmState.Encap),
		"esn":           childSecurityAssociation.EsnInfo.GetNeedESN(),
		"encrAlgo":      xfrmEncryptionAlgorithm.Name,
		"encrKeyFp":     keyFingerprint(xfrmEncryptionAlgorithm.Key),
		"encrKeyLen":    len(xfrmEncryptionAlgorithm.Key),
		"integAlgo":     algoNameOrEmpty(xfrmIntegrityAlgorithm),
		"integKeyFp":    keyFingerprint(keyOrNil(xfrmIntegrityAlgorithm)),
		"integKeyLen":   keyLenOrZero(xfrmIntegrityAlgorithm),
		"integTruncLen": truncLenOrZero(xfrmIntegrityAlgorithm),
	}).Trace("XFRM: applying outbound state/policy")

	// Commit xfrm state to netlink
	if outboundReplay != nil {
		err = xfrmStateAddOrUpdateWithReplay(xfrmState, outboundReplay)
	} else {
		err = xfrmStateAddOrUpdate(xfrmState)
	}
	if err != nil {
		return errors.Wrapf(err, "Add XFRM state")
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = xfrmPolicyAddOrUpdate(xfrmPolicy); err != nil {
		return errors.Wrapf(err, "Add XFRM policy")
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)
	return nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func keyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	// Short fingerprint (12 hex chars) is enough for correlation across logs without exposing secrets.
	return fmt.Sprintf("%x", sum[:6])
}

func algoNameOrEmpty(algo *netlink.XfrmStateAlgo) string {
	if algo == nil {
		return ""
	}
	return algo.Name
}

func keyOrNil(algo *netlink.XfrmStateAlgo) []byte {
	if algo == nil {
		return nil
	}
	return algo.Key
}

func keyLenOrZero(algo *netlink.XfrmStateAlgo) int {
	if algo == nil {
		return 0
	}
	return len(algo.Key)
}

func truncLenOrZero(algo *netlink.XfrmStateAlgo) int {
	if algo == nil {
		return 0
	}
	return algo.TruncateLen
}

func encapTypeString(encap *netlink.XfrmStateEncap) string {
	if encap == nil {
		return ""
	}
	switch encap.Type {
	case netlink.XFRM_ENCAP_ESPINUDP:
		return "espinudp"
	default:
		return fmt.Sprintf("%d", encap.Type)
	}
}

func encapPortSrc(encap *netlink.XfrmStateEncap) int {
	if encap == nil {
		return 0
	}
	return int(encap.SrcPort) // #nosec G115
}

func encapPortDst(encap *netlink.XfrmStateEncap) int {
	if encap == nil {
		return 0
	}
	return int(encap.DstPort) // #nosec G115
}

func encapOrigAddr(encap *netlink.XfrmStateEncap) string {
	if encap == nil {
		return ""
	}
	return ipString(encap.OriginalAddress)
}

func xfrmStateAddOrUpdate(state *netlink.XfrmState) error {
	if state == nil {
		return nil
	}
	if err := netlink.XfrmStateAdd(state); err != nil {
		// netlink does not export syscall.EEXIST; match the iproute2-style string.
		if strings.Contains(err.Error(), "file exists") {
			return netlink.XfrmStateUpdate(state)
		}
		return err
	}
	return nil
}

func xfrmPolicyAddOrUpdate(policy *netlink.XfrmPolicy) error {
	if policy == nil {
		return nil
	}
	if err := netlink.XfrmPolicyAdd(policy); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			return netlink.XfrmPolicyUpdate(policy)
		}
		return err
	}
	return nil
}

func SetupIPsecXfrmi(xfrmIfaceName, parentIfaceName string, xfrmIfaceId uint32,
	xfrmIfaceAddr net.IPNet,
) (netlink.Link, error) {
	ikeLog := logger.IKELog
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, fmt.Errorf("Cannot find parent interface %s by name: %+v", parentIfaceName, err)
	}

	//Aggiungo di test MTU hardcoded 1380
	if err = netlink.LinkSetMTU(parent, 1380); err != nil {
		return nil, fmt.Errorf("Cannot set MTU %d to parent interface %s: %+v", 1380, parentIfaceName, err)
	}

	// ip link add <xfrmIfaceName> type xfrm dev <parent.Attrs().Name> if_id <xfrmIfaceId>
	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name:        xfrmIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Ifid: xfrmIfaceId,
	}

	if err = netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		return nil, err
	}

	ikeLog.Debugf("XFRM interface %s index is %d", xfrmIfaceName, xfrmi.Attrs().Index)

	// ip addr add xfrmIfaceAddr dev <xfrmIfaceName>
	linkIPSecAddr := &netlink.Addr{
		IPNet: &xfrmIfaceAddr,
	}

	if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil {
		return nil, err
	}

	// ip link set <xfrmIfaceName> up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	return xfrmi, nil
}

func getTruncateLength(transformID uint16) int {
	switch transformID {
	case message.AUTH_HMAC_MD5_96:
		return 96
	case message.AUTH_HMAC_SHA1_96:
		return 96
	case message.AUTH_HMAC_SHA2_256_128:
		return 128
	default:
		return 96
	}
}
