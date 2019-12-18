#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "x509-asn1.h"
#include "x509_rsakey-asn1.h"
#include "x509_cert.h"
#include "oid_registry.h"
#include "misc.h"

struct x509_parse_context {
	struct x509_certificate	*cert;		/* Certificate being constructed */
	unsigned long	data;			/* Start of data */
	const void	*cert_start;		/* Start of cert content */
	const void	*key;			/* Key data */
	size_t		key_size;		/* Size of key data */
	enum OID	last_oid;		/* Last OID encountered */
	enum OID	algo_oid;		/* Algorithm OID */
	unsigned char	nr_mpi;			/* Number of MPIs stored */
	u8		o_size;			/* Size of organizationName (O) */
	u8		cn_size;		/* Size of commonName (CN) */
	u8		email_size;		/* Size of emailAddress */
	u16		o_offset;		/* Offset of organizationName (O) */
	u16		cn_offset;		/* Offset of commonName (CN) */
	u16		email_offset;		/* Offset of emailAddress */
};

/*
 * Free an X.509 certificate
 */
void x509_free_certificate(struct x509_certificate *cert)
{
	if (cert) {
		free(cert->issuer);
		free(cert->subject);
		free(cert->fingerprint);
		free(cert->authority);
		free(cert);
	}
}

/*
 * Parse an X.509 certificate
 */
struct x509_certificate *x509_cert_parse(const void *data, size_t datalen)
{
	struct x509_certificate *cert;
	struct x509_parse_context *ctx;
	long ret;

	ret = -ENOMEM;
	cert = calloc(1, sizeof(struct x509_certificate));
	if (!cert)
		goto error_no_cert;
	ctx = calloc(1, sizeof(struct x509_parse_context));
	if (!ctx)
		goto error_no_ctx;

	ctx->cert = cert;
	ctx->data = (unsigned long)data;

	/* Attempt to decode the certificate */
	ret = asn1_ber_decoder(&x509_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	/* Decode the public key */
	ret = asn1_ber_decoder(&x509_rsakey_decoder, ctx,
			       ctx->key, ctx->key_size);
	if (ret < 0)
		goto error_decode;

	free(ctx);
	return cert;

error_decode:
	free(ctx);
error_no_ctx:
	x509_free_certificate(cert);
error_no_cert:
	return NULL;
}

/*
 * Fabricate and save the issuer and subject names
 */
static int x509_fabricate_name(struct x509_parse_context *ctx, size_t hdrlen, unsigned char tag, char **_name, size_t vlen)
{
	const void *name, *data = (const void *)ctx->data;
	size_t namesize;
	char *buffer;

	if (*_name)
		return -EINVAL;

	/* Empty name string if no material */
	if (!ctx->cn_size && !ctx->o_size && !ctx->email_size) {
		buffer = malloc(1);
		if (!buffer)
			return -ENOMEM;
		buffer[0] = 0;
		goto done;
	}

	if (ctx->cn_size && ctx->o_size) {
		/* Consider combining O and CN, but use only the CN if it is
		 * prefixed by the O, or a significant portion thereof.
		 */
		namesize = ctx->cn_size;
		name = data + ctx->cn_offset;
		if (ctx->cn_size >= ctx->o_size &&
		    memcmp(data + ctx->cn_offset, data + ctx->o_offset,
			   ctx->o_size) == 0)
			goto single_component;
		if (ctx->cn_size >= 7 &&
		    ctx->o_size >= 7 &&
		    memcmp(data + ctx->cn_offset, data + ctx->o_offset, 7) == 0)
			goto single_component;

		buffer = malloc(ctx->o_size + 2 + ctx->cn_size + 1);
		if (!buffer)
			return -ENOMEM;

		memcpy(buffer,
		       data + ctx->o_offset, ctx->o_size);
		buffer[ctx->o_size + 0] = ':';
		buffer[ctx->o_size + 1] = ' ';
		memcpy(buffer + ctx->o_size + 2,
		       data + ctx->cn_offset, ctx->cn_size);
		buffer[ctx->o_size + 2 + ctx->cn_size] = 0;
		goto done;

	} else if (ctx->cn_size) {
		namesize = ctx->cn_size;
		name = data + ctx->cn_offset;
	} else if (ctx->o_size) {
		namesize = ctx->o_size;
		name = data + ctx->o_offset;
	} else {
		namesize = ctx->email_size;
		name = data + ctx->email_offset;
	}

single_component:
	buffer = malloc(namesize + 1);
	if (!buffer)
		return -ENOMEM;
	memcpy(buffer, name, namesize);
	buffer[namesize] = 0;

done:
	*_name = buffer;
	ctx->cn_size = 0;
	ctx->o_size = 0;
	ctx->email_size = 0;
	return 0;
}

/**
 * x509_decode_time - Decode an X.509 time ASN.1 object
 * @_t: The time to fill in
 * @hdrlen: The length of the object header
 * @tag: The object tag
 * @value: The object value
 * @vlen: The size of the object value
 *
 * Decode an ASN.1 universal time or generalised time field into a struct the
 * kernel can handle and check it for validity.  The time is decoded thus:
 *
 *	[RFC5280 §4.1.2.5]
 *	CAs conforming to this profile MUST always encode certificate validity
 *	dates through the year 2049 as UTCTime; certificate validity dates in
 *	2050 or later MUST be encoded as GeneralizedTime.  Conforming
 *	applications MUST be able to process validity dates that are encoded in
 *	either UTCTime or GeneralizedTime.
 */
int x509_decode_time(time64_t *_t,  size_t hdrlen,
		     unsigned char tag,
		     const unsigned char *value, size_t vlen)
{
	static const unsigned char month_lengths[] = { 31, 28, 31, 30, 31, 30,
						       31, 31, 30, 31, 30, 31 };
	const unsigned char *p = value;
	unsigned year, mon, day, hour, min, sec, mon_len;

#define dec2bin(X) ({ unsigned char x = (X) - '0'; if (x > 9) goto invalid_time; x; })
#define DD2bin(P) ({ unsigned x = dec2bin(P[0]) * 10 + dec2bin(P[1]); P += 2; x; })

	if (tag == ASN1_UNITIM) {
		/* UTCTime: YYMMDDHHMMSSZ */
		if (vlen != 13)
			goto unsupported_time;
		year = DD2bin(p);
		if (year >= 50)
			year += 1900;
		else
			year += 2000;
	} else if (tag == ASN1_GENTIM) {
		/* GenTime: YYYYMMDDHHMMSSZ */
		if (vlen != 15)
			goto unsupported_time;
		year = DD2bin(p) * 100 + DD2bin(p);
		if (year >= 1950 && year <= 2049)
			goto invalid_time;
	} else {
		goto unsupported_time;
	}

	mon  = DD2bin(p);
	day = DD2bin(p);
	hour = DD2bin(p);
	min  = DD2bin(p);
	sec  = DD2bin(p);

	if (*p != 'Z')
		goto unsupported_time;

	if (year < 1970 ||
	    mon < 1 || mon > 12)
		goto invalid_time;

	mon_len = month_lengths[mon - 1];
	if (mon == 2) {
		if (year % 4 == 0) {
			mon_len = 29;
			if (year % 100 == 0) {
				mon_len = 28;
				if (year % 400 == 0)
					mon_len = 29;
			}
		}
	}

	if (day < 1 || day > mon_len ||
	    hour > 24 || /* ISO 8601 permits 24:00:00 as midnight tomorrow */
	    min > 59 ||
	    sec > 60) /* ISO 8601 permits leap seconds [X.680 46.3] */
		goto invalid_time;

	struct tm t = {
		.tm_year = year,
		.tm_mon = mon,
		.tm_mday = day,
		.tm_hour = hour,
		.tm_min = min,
		.tm_sec = sec,
	};
	*_t = mktime(&t);
	return 0;

unsupported_time:
	pr_debug("Got unsupported time [tag %02x]: '%*phN'\n",
		 tag, (int)vlen, value);
	return -EBADMSG;
invalid_time:
	pr_debug("Got invalid time [tag %02x]: '%*phN'\n",
		 tag, (int)vlen, value);
	return -EBADMSG;
}

/*
 * Extract the data for the public key algorithm
 */
int x509_extract_key_data(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_extract_key_data %p %lu\n", value, vlen);
	if (ctx->last_oid != OID_rsaEncryption)
		return -ENOPKG;

	/* Discard the BIT STRING metadata */
	ctx->key = value + 1;
	ctx->key_size = vlen - 1;
	return 0;
}

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int x509_extract_name_segment(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_extract_name_segment %p %lu\n", value, vlen);
	switch (ctx->last_oid) {
	case OID_commonName:
		ctx->cn_size = vlen;
		ctx->cn_offset = (unsigned long)value - ctx->data;
		break;
	case OID_organizationName:
		ctx->o_size = vlen;
		ctx->o_offset = (unsigned long)value - ctx->data;
		break;
	case OID_email_address:
		ctx->email_size = vlen;
		ctx->email_offset = (unsigned long)value - ctx->data;
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int x509_note_OID(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_note_OID %p %lu\n", value, vlen);
	ctx->last_oid = look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		pr_debug("Unknown OID: [%lu] %s\n",
			 (unsigned long)value - ctx->data, buffer);
	}
	return 0;
}

int x509_note_issuer(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	int ret;
	char * name;
	pr_debug("x509_note_issuer %p %lu\n", value, vlen);
	ctx->cert->raw_issuer = value;
	ctx->cert->raw_issuer_size = vlen;
	return x509_fabricate_name(ctx, hdrlen, tag, &ctx->cert->issuer, vlen);
}

int x509_note_not_before(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	pr_debug("x509_note_not_before %p %lu\n", value, vlen);
	return x509_decode_time(&ctx->cert->valid_from, hdrlen, tag, value, vlen);
}

int x509_note_not_after(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	pr_debug("x509_note_not_after %p %lu\n", value, vlen);
	return x509_decode_time(&ctx->cert->valid_to, hdrlen, tag, value, vlen);
}

int x509_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("PubKey Algo: %u\n", ctx->last_oid);

	pr_debug("x509_note_pkey_algo %p %lu\n", value, vlen);
	switch (ctx->last_oid) {
	case OID_md2WithRSAEncryption:
	case OID_md3WithRSAEncryption:
	default:
		return -ENOPKG; /* Unsupported combination */

	case OID_md4WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_MD5 pkey_algo PKEY_ALGO_RSA\n");
		break;

	case OID_sha1WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_SHA1 pkey_algo PKEY_ALGO_RSA\n");
		break;

	case OID_sha256WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_SHA256 pkey_algo PKEY_ALGO_RSA\n");
		break;

	case OID_sha384WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_SHA384 pkey_algo PKEY_ALGO_RSA\n");
		break;

	case OID_sha512WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_SHA512 pkey_algo PKEY_ALGO_RSA\n");
		break;

	case OID_sha224WithRSAEncryption:
		puts("pkey_hash_algo HASH_ALGO_SHA224 pkey_algo PKEY_ALGO_RSA\n");
		break;
	}

	ctx->algo_oid = ctx->last_oid;
	return 0;
}

/*
 * Note the certificate serial number
 */
int x509_note_serial(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	pr_debug("x509_note_serial %p %lu\n", value, vlen);
	ctx->cert->raw_serial = value;
	ctx->cert->raw_serial_size = vlen;
	return 0;
}

int x509_note_signature(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_note_signature %p %lu\n", value, vlen);

	pr_debug("Signature type: %u size %zu\n", ctx->last_oid, vlen);

	if (ctx->last_oid != ctx->algo_oid) {
		pr_warn("WARNING: Got cert with pkey (%u) and sig (%u) algorithm OIDs\n",
			ctx->algo_oid, ctx->last_oid);
		return -EINVAL;
	}

	ctx->cert->raw_sig = value;
	ctx->cert->raw_sig_size = vlen;
	return 0;
}

int x509_note_subject(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	pr_debug("x509_note_subject %p %lu\n", value, vlen);
	ctx->cert->raw_subject = value;
	ctx->cert->raw_subject_size = vlen;
	return x509_fabricate_name(ctx, hdrlen, tag, &ctx->cert->subject, vlen);
}

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int x509_note_tbs_certificate(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_note_tbs_certificate %p %lu\n", value, vlen);

	pr_debug("x509_note_tbs_certificate(,%zu,%02x,%ld,%zu)!\n",
		 hdrlen, tag, (unsigned long)value - ctx->data, vlen);

	ctx->cert->tbs = value - hdrlen;
	ctx->cert->tbs_size = vlen + hdrlen;
	return 0;
}

/*
 * Extract a RSA public key value
 */
int rsa_extract_mpi(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	//We don't actually care about getting the key here
	//and trying to compile in the MPI library is too much work
#if 0
	struct x509_parse_context *ctx = context;
	MPI mpi;

	if (ctx->nr_mpi >= ARRAY_SIZE(ctx->cert->pub->mpi)) {
		pr_err("Too many public key MPIs in certificate\n");
		return -EBADMSG;
	}

	mpi = mpi_read_raw_data(value, vlen);
	if (!mpi)
		return -ENOMEM;

	ctx->cert->pub->mpi[ctx->nr_mpi++] = mpi;
#endif
	return 0;
}

/* The keyIdentifier in AuthorityKeyIdentifier SEQUENCE is tag(CONT,PRIM,0) */
#define SEQ_TAG_KEYID (ASN1_CONT << 6)

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int x509_process_extension(void *context, size_t hdrlen, unsigned char tag, const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	const unsigned char *v = value;
	char *f;
	int i;

	pr_debug("x509_process_extension %p %lu\n", value, vlen);
	pr_debug("Extension: %u\n", ctx->last_oid);

	if (ctx->last_oid == OID_subjectKeyIdentifier) {
		/* Get hold of the key fingerprint */
		if (vlen < 3)
			return -EBADMSG;
		if (v[0] != ASN1_OTS || v[1] != vlen - 2)
			return -EBADMSG;
		v += 2;
		vlen -= 2;

		f = malloc(vlen * 2 + 1);
		if (!f)
			return -ENOMEM;
		for (i = 0; i < vlen; i++)
			sprintf(f + i * 2, "%02x", v[i]);
		pr_debug("fingerprint %s\n", f);
		ctx->cert->fingerprint = f;
		return 0;
	}

	if (ctx->last_oid == OID_authorityKeyIdentifier) {
		size_t key_len;

		/* Get hold of the CA key fingerprint */
		if (vlen < 5)
			return -EBADMSG;

		/* Authority Key Identifier must be a Constructed SEQUENCE */
		if (v[0] != (ASN1_SEQ | (ASN1_CONS << 5)))
			return -EBADMSG;

		/* Authority Key Identifier is not indefinite length */
		if (unlikely(vlen == ASN1_INDEFINITE_LENGTH))
			return -EBADMSG;

		if (vlen < ASN1_INDEFINITE_LENGTH) {
			/* Short Form length */
			if (v[1] != vlen - 2 ||
			    v[2] != SEQ_TAG_KEYID ||
			    v[3] > vlen - 4)
				return -EBADMSG;

			key_len = v[3];
			v += 4;
		} else {
			/* Long Form length */
			size_t seq_len = 0;
			size_t sub = v[1] - ASN1_INDEFINITE_LENGTH;

			if (sub > 2)
				return -EBADMSG;

			/* calculate the length from subsequent octets */
			v += 2;
			for (i = 0; i < sub; i++) {
				seq_len <<= 8;
				seq_len |= v[i];
			}

			if (seq_len != vlen - 2 - sub ||
			    v[sub] != SEQ_TAG_KEYID ||
			    v[sub + 1] > vlen - 4 - sub)
				return -EBADMSG;

			key_len = v[sub + 1];
			v += (sub + 2);
		}

		f = malloc(key_len * 2 + 1);
		if (!f)
			return -ENOMEM;
		for (i = 0; i < key_len; i++)
			sprintf(f + i * 2, "%02x", v[i]);
		pr_debug("authority   %s\n", f);
		ctx->cert->authority = f;
		return 0;
	}

	return 0;
}

