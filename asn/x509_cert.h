#ifndef __X509_CERT_H__
#define __X509_CERT_H__

#include "misc.h"

struct x509_certificate {
	struct x509_certificate *next;
	struct x509_certificate *signer;  /* Certificate that signed this one */
	char		*issuer;		/* Name of certificate issuer */
	char		*subject;		/* Name of certificate subject */
	char		*fingerprint;		/* Key fingerprint as hex */
	char		*authority;		/* Authority key fingerprint as hex */
	time64_t	valid_from;
	time64_t	valid_to;
	const void	*tbs;			/* Signed data */
	unsigned	tbs_size;		/* Size of signed data */
	unsigned	raw_sig_size;		/* Size of sigature */
	const void	*raw_sig;		/* Signature data */
	const void	*raw_serial;		/* Raw serial number in ASN.1 */
	unsigned	raw_serial_size;
	unsigned	raw_issuer_size;
	const void	*raw_issuer;		/* Raw issuer name in ASN.1 */
	const void	*raw_subject;		/* Raw subject name in ASN.1 */
	unsigned	raw_subject_size;
	unsigned	index;
};

void x509_free_certificate(struct x509_certificate *cert);
struct x509_certificate *x509_cert_parse(const void *data, size_t datalen);

#endif //__X509_CERT_H__
