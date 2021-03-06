/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for x509
 */
#include "asn1_ber_bytecode.h"
#include "x509-asn1.h"

enum x509_actions {
	ACT_x509_extract_key_data = 0,
	ACT_x509_extract_name_segment = 1,
	ACT_x509_note_OID = 2,
	ACT_x509_note_issuer = 3,
	ACT_x509_note_not_after = 4,
	ACT_x509_note_not_before = 5,
	ACT_x509_note_pkey_algo = 6,
	ACT_x509_note_serial = 7,
	ACT_x509_note_signature = 8,
	ACT_x509_note_subject = 9,
	ACT_x509_note_tbs_certificate = 10,
	ACT_x509_process_extension = 11,
	NR__x509_actions = 12
};

static const asn1_action_t x509_action_table[NR__x509_actions] = {
	[   0] = x509_extract_key_data,
	[   1] = x509_extract_name_segment,
	[   2] = x509_note_OID,
	[   3] = x509_note_issuer,
	[   4] = x509_note_not_after,
	[   5] = x509_note_not_before,
	[   6] = x509_note_pkey_algo,
	[   7] = x509_note_serial,
	[   8] = x509_note_signature,
	[   9] = x509_note_subject,
	[  10] = x509_note_tbs_certificate,
	[  11] = x509_process_extension,
};

static const unsigned char x509_machine[] = {
	// Certificate
	[   0] = ASN1_OP_MATCH,
	[   1] = _tag(UNIV, CONS, SEQ),
	// TBSCertificate
	[   2] =  ASN1_OP_MATCH,
	[   3] =  _tag(UNIV, CONS, SEQ),
	[   4] =   ASN1_OP_MATCH_JUMP_OR_SKIP,		// version
	[   5] =   _tagn(CONT, CONS,  0),
	[   6] =   _jump_target(70),
	// CertificateSerialNumber
	[   7] =   ASN1_OP_MATCH,
	[   8] =   _tag(UNIV, PRIM, INT),
	[   9] =   ASN1_OP_ACT,
	[  10] =   _action(ACT_x509_note_serial),
	// AlgorithmIdentifier
	[  11] =   ASN1_OP_MATCH_JUMP,
	[  12] =   _tag(UNIV, CONS, SEQ),
	[  13] =   _jump_target(74),		// --> AlgorithmIdentifier
	[  14] =   ASN1_OP_ACT,
	[  15] =   _action(ACT_x509_note_pkey_algo),
	// Name
	[  16] =   ASN1_OP_MATCH_JUMP,
	[  17] =   _tag(UNIV, CONS, SEQ),
	[  18] =   _jump_target(80),		// --> Name
	[  19] =   ASN1_OP_ACT,
	[  20] =   _action(ACT_x509_note_issuer),
	// Validity
	[  21] =   ASN1_OP_MATCH,
	[  22] =   _tag(UNIV, CONS, SEQ),
	// Time
	[  23] =    ASN1_OP_MATCH_OR_SKIP,		// utcTime
	[  24] =    _tag(UNIV, PRIM, UNITIM),
	[  25] =    ASN1_OP_COND_MATCH_OR_SKIP,		// generalTime
	[  26] =    _tag(UNIV, PRIM, GENTIM),
	[  27] =    ASN1_OP_COND_FAIL,
	[  28] =    ASN1_OP_ACT,
	[  29] =    _action(ACT_x509_note_not_before),
	// Time
	[  30] =    ASN1_OP_MATCH_OR_SKIP,		// utcTime
	[  31] =    _tag(UNIV, PRIM, UNITIM),
	[  32] =    ASN1_OP_COND_MATCH_OR_SKIP,		// generalTime
	[  33] =    _tag(UNIV, PRIM, GENTIM),
	[  34] =    ASN1_OP_COND_FAIL,
	[  35] =    ASN1_OP_ACT,
	[  36] =    _action(ACT_x509_note_not_after),
	[  37] =   ASN1_OP_END_SEQ,
	// Name
	[  38] =   ASN1_OP_MATCH_JUMP,
	[  39] =   _tag(UNIV, CONS, SEQ),
	[  40] =   _jump_target(80),		// --> Name
	[  41] =   ASN1_OP_ACT,
	[  42] =   _action(ACT_x509_note_subject),
	// SubjectPublicKeyInfo
	[  43] =   ASN1_OP_MATCH,
	[  44] =   _tag(UNIV, CONS, SEQ),
	// AlgorithmIdentifier
	[  45] =    ASN1_OP_MATCH_JUMP,
	[  46] =    _tag(UNIV, CONS, SEQ),
	[  47] =    _jump_target(74),		// --> AlgorithmIdentifier
	[  48] =    ASN1_OP_MATCH_ACT,		// subjectPublicKey
	[  49] =    _tag(UNIV, PRIM, BTS),
	[  50] =    _action(ACT_x509_extract_key_data),
	[  51] =   ASN1_OP_END_SEQ,
	// UniqueIdentifier
	[  52] =   ASN1_OP_MATCH_OR_SKIP,		// issuerUniqueID
	[  53] =   _tagn(CONT, PRIM,  1),
	// UniqueIdentifier
	[  54] =   ASN1_OP_MATCH_OR_SKIP,		// subjectUniqueID
	[  55] =   _tagn(CONT, PRIM,  2),
	[  56] =   ASN1_OP_MATCH_JUMP_OR_SKIP,		// extensions
	[  57] =   _tagn(CONT, CONS,  3),
	[  58] =   _jump_target(95),
	[  59] =  ASN1_OP_END_SEQ,
	[  60] =  ASN1_OP_ACT,
	[  61] =  _action(ACT_x509_note_tbs_certificate),
	// AlgorithmIdentifier
	[  62] =  ASN1_OP_MATCH_JUMP,
	[  63] =  _tag(UNIV, CONS, SEQ),
	[  64] =  _jump_target(74),		// --> AlgorithmIdentifier
	[  65] =  ASN1_OP_MATCH_ACT,		// signature
	[  66] =  _tag(UNIV, PRIM, BTS),
	[  67] =  _action(ACT_x509_note_signature),
	[  68] = ASN1_OP_END_SEQ,
	[  69] = ASN1_OP_COMPLETE,

	// Version
	[  70] =  ASN1_OP_MATCH,
	[  71] =  _tag(UNIV, PRIM, INT),
	[  72] = ASN1_OP_END_SEQ,
	[  73] = ASN1_OP_RETURN,

	[  74] =  ASN1_OP_MATCH_ACT,		// algorithm
	[  75] =  _tag(UNIV, PRIM, OID),
	[  76] =  _action(ACT_x509_note_OID),
	[  77] =  ASN1_OP_MATCH_ANY_OR_SKIP,		// parameters
	[  78] = ASN1_OP_END_SEQ,
	[  79] = ASN1_OP_RETURN,

	// RelativeDistinguishedName
	[  80] =  ASN1_OP_MATCH,
	[  81] =  _tag(UNIV, CONS, SET),
	// AttributeValueAssertion
	[  82] =   ASN1_OP_MATCH,
	[  83] =   _tag(UNIV, CONS, SEQ),
	[  84] =    ASN1_OP_MATCH_ACT,		// attributeType
	[  85] =    _tag(UNIV, PRIM, OID),
	[  86] =    _action(ACT_x509_note_OID),
	[  87] =    ASN1_OP_MATCH_ANY_ACT,		// attributeValue
	[  88] =    _action(ACT_x509_extract_name_segment),
	[  89] =   ASN1_OP_END_SEQ,
	[  90] =  ASN1_OP_END_SET_OF,
	[  91] =  _jump_target(82),
	[  92] = ASN1_OP_END_SEQ_OF,
	[  93] = _jump_target(80),
	[  94] = ASN1_OP_RETURN,

	// Extensions
	[  95] =  ASN1_OP_MATCH,
	[  96] =  _tag(UNIV, CONS, SEQ),
	// Extension
	[  97] =   ASN1_OP_MATCH,
	[  98] =   _tag(UNIV, CONS, SEQ),
	[  99] =    ASN1_OP_MATCH_ACT,		// extnid
	[ 100] =    _tag(UNIV, PRIM, OID),
	[ 101] =    _action(ACT_x509_note_OID),
	[ 102] =    ASN1_OP_MATCH_OR_SKIP,		// critical
	[ 103] =    _tag(UNIV, PRIM, BOOL),
	[ 104] =    ASN1_OP_MATCH_ACT,		// extnValue
	[ 105] =    _tag(UNIV, PRIM, OTS),
	[ 106] =    _action(ACT_x509_process_extension),
	[ 107] =   ASN1_OP_END_SEQ,
	[ 108] =  ASN1_OP_END_SEQ_OF,
	[ 109] =  _jump_target(97),
	[ 110] = ASN1_OP_END_SEQ,
	[ 111] = ASN1_OP_RETURN,
};

const struct asn1_decoder x509_decoder = {
	.machine = x509_machine,
	.machlen = sizeof(x509_machine),
	.actions = x509_action_table,
};
