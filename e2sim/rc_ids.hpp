#ifndef E2SIM_RC_IDS_HPP
#define E2SIM_RC_IDS_HPP

// Shared constants for the RC RAN function. Using inline constexpr avoids
// duplicate definitions across translation units.
inline constexpr long kRcControlStyleTypeHandover = 3;
inline constexpr long kRcControlActionIdHandover = 1;

inline constexpr long kRcParamUeId = 41001;
inline constexpr long kRcParamTargetCellPci = 45001;
inline constexpr long kRcParamTargetGNbId = 45002;
inline constexpr long kRcParamHoCause = 45010;

inline constexpr long kRcOutcomeStatus = 50001;
inline constexpr long kRcOutcomeNotes = 50002;

#endif  // E2SIM_RC_IDS_HPP
