#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>



extern "C" {
#include "E2SM-KPM-RANfunction-Description.h"
#include "e2ap_asn1c_codec.h"
#include "GlobalE2node-ID.h"
#include "GlobalE2node-gNB-ID.h"
#include "GlobalgNB-ID.h"
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "GNB-ID-Choice.h"
#include "ProtocolIE-Field.h"
#include "E2setupRequest.h"
#include "RICaction-ToBeSetup-Item.h"
#include "RICactions-ToBeSetup-List.h"
#include "RICeventTriggerDefinition.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "ProtocolIE-SingleContainer.h"
#include "RANfunctions-List.h"
#include "RICindication.h"
#include "RICsubsequentActionType.h"
#include "RICsubsequentAction.h"
#include "RICtimeToWait.h"
}

struct timespec ts;

//String ammettendo n variabili variabili
 void stampaln(const char* msg, ...) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long seconds = now.tv_sec - ts.tv_sec;
    long nseconds = now.tv_nsec - ts.tv_nsec;
    if (nseconds < 0) {
        seconds -= 1;
        nseconds += 1000000000L;
    }
    printf("[%ld.%09ld] ", seconds, nseconds);
    va_list args;
    va_start(args, msg);
    vprintf(msg, args);
    va_end(args);
    fflush(stdout);
}
// Ritorna il numero di bit effettivi (size*8 - bits_unused)
static inline int bit_length(const BIT_STRING_t& bs) {
  if (!bs.buf || bs.size <= 0 || bs.bits_unused < 0 || bs.bits_unused > 7) return -1;
  return bs.size * 8 - bs.bits_unused;
}

// Copia di sicurezza per (ri)allocare il buffer
static bool realloc_and_zero(uint8_t** buf, int new_size) {
  uint8_t* nb = (uint8_t*)calloc(1, new_size);
  if (!nb) return false;
  free(*buf);
  *buf = nb;
  return true;
}

/**
 * Valida o corregge la lunghezza del gNB ID:
 * - Se 22 <= len <= 32: OK (nessuna modifica)
 * - Se len < 22: left-pad a 22 mantenendo il valore
 * - Se len > 32: errore
 *
 * Ritorna 0 se OK (o dopo fix), -1 se errore.
 */
int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits = 22,
                                  int max_bits = 32,
                                  int target_if_pad = 22) {
  if (!gnb_id_bs) return -1;
  if (min_bits < 1 || max_bits < min_bits) return -1;

  int total_bits = bit_length(*gnb_id_bs);
  if (total_bits < 0) return -1;

  if (total_bits > max_bits) {
    // Non tronchiamo: meglio segnalare errore
    stampaln("gNB ID too long: %d bits (max %d)\n", total_bits, max_bits);
    return -1;
  }

  if (total_bits >= min_bits && total_bits <= max_bits) {
    // Già valido: nessuna azione
    return 0;
  }

  // total_bits < min_bits -> left-pad a target_if_pad (tipicamente 22)
  const int target_bits = target_if_pad;
  if (target_bits < min_bits || target_bits > max_bits) return -1;

  // 1) Ricostruisci il valore intero corrente (big-endian), rimuovendo i bits_unused
  uint64_t value = 0;
  for (int i = 0; i < gnb_id_bs->size; ++i) {
    value = (value << 8) | gnb_id_bs->buf[i];
  }
  // Rimuove gli unused bit (in coda all'ultimo byte)
  if (gnb_id_bs->bits_unused > 0) {
    value >>= gnb_id_bs->bits_unused;
  }

  // A questo punto 'value' rappresenta i 'total_bits' effettivi del gNB ID.
  // 2) Prepara il nuovo contenitore con target_bits
  const int num_bytes = (target_bits + 7) / 8;
  const int bits_unused_new = num_bytes * 8 - target_bits;

  if (!realloc_and_zero(&gnb_id_bs->buf, num_bytes)) {
    return -1;
  }
  gnb_id_bs->size = num_bytes;
  gnb_id_bs->bits_unused = bits_unused_new;

  // 3) Inserisci il valore nei target_bits *senza* cambiarlo (vero left-pad)
  // Per codifica ASN.1 BIT STRING: i bit inutilizzati sono in coda ⇒ shiftiamo a sinistra di bits_unused_new
  uint64_t out = value;
  out <<= bits_unused_new;

  // 4) Scrivi in big-endian
  for (int i = num_bytes - 1; i >= 0; --i) {
    gnb_id_bs->buf[i] = static_cast<uint8_t>(out & 0xFF);
    out >>= 8;
  }

  return 0;
}