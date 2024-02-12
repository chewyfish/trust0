OPENSSL_CMD=openssl

# Params - Key Algorithm

OPENSSL_KEYALG_RSA_TYPE=rsa
OPENSSL_KEYALG_RSA_PARAMS=4096
OPENSSL_KEYALG_EC_TYPE=ec
OPENSSL_KEYALG_EC_PARAMS=${EXAMPLE_BUILD_DIR}/ecparams.pem
#OPENSSL_KEYALG_EC_CURVE=secp384r1
OPENSSL_KEYALG_EC_CURVE=prime256v1
OPENSSL_KEYALG_ED_TYPE=ed
OPENSSL_KEYALG_ED_PARAMS=ed25519

# Update these 2 values to switch key algorithm type and params
OPENSSL_KEYALG_TYPE=${OPENSSL_KEYALG_RSA_TYPE}
OPENSSL_KEYALG_PARAMS=${OPENSSL_KEYALG_RSA_PARAMS}

# PKI Provider Targets - ROOT CA

generate-root-ca-pki-resources: ${ROOT_CA__PKI_CRL_CONF_FILE}
	@echo "Creating root CA PKI resources"
	@([ '${OPENSSL_KEYALG_TYPE}' != '${OPENSSL_KEYALG_EC_TYPE}' ] || [ -f ${OPENSSL_KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${OPENSSL_KEYALG_EC_CURVE} -out ${OPENSSL_KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} rootca-pki-creator --rootca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --rootca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${OPENSSL_KEYALG_TYPE}:${OPENSSL_KEYALG_PARAMS} --subj-common-name ${ROOT_CA__PKI_SUBJ_COMMONNAME} --subj-country ${ROOT_CA__PKI_SUBJ_COUNTRY} --subj-state ${ROOT_CA__PKI_SUBJ_STATE} --subj-city ${ROOT_CA__PKI_SUBJ_CITY} --subj-company ${ROOT_CA__PKI_SUBJ_COMPANY} --subj-dept ${ROOT_CA__PKI_SUBJ_DEPT}
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CRL_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	@cat <<- EOF > $@
		[ ca ]
		default_ca = ca_default
		[ ca_default ]
		database = ${ROOT_CA__PKI_DATABASE_FILE}
		crlnumber = ${ROOT_CA__PKI_CRLNUMBER_FILE}
		default_md = default
		crl_extensions = crl_ext
		[ crl_ext ]
		authorityKeyIdentifier = keyid,issuer
		EOF
	@echo ""

# PKI Provider Targets - Trust Gateway

generate-gateway-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating gateway PKI resources"
	@([ '${OPENSSL_KEYALG_TYPE}' != '${OPENSSL_KEYALG_EC_TYPE}' ] || [ -f ${OPENSSL_KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${OPENSSL_KEYALG_EC_CURVE} -out ${OPENSSL_KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} gateway-pki-creator --gateway-cert-filepath ${TRUST0_GATEWAY__PKI_CERT_FILE} --gateway-key-filepath ${TRUST0_GATEWAY__PKI_KEY_FILE} --ca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --ca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${OPENSSL_KEYALG_TYPE}:${OPENSSL_KEYALG_PARAMS} --subj-common-name ${TRUST0_GATEWAY__PKI_SUBJ_COMMONNAME} --subj-country ${TRUST0_GATEWAY__PKI_SUBJ_COUNTRY} --subj-state ${TRUST0_GATEWAY__PKI_SUBJ_STATE} --subj-city ${TRUST0_GATEWAY__PKI_SUBJ_CITY} --subj-company ${TRUST0_GATEWAY__PKI_SUBJ_COMPANY} --subj-dept ${TRUST0_GATEWAY__PKI_SUBJ_DEPT} --san-dns1 ${TRUST0_GATEWAY__PKI_HOST_DNS1} --san-dns2 ${TRUST0_GATEWAY__PKI_HOST_DNS2}
	@echo ""

# PKI Provider Targets - Trust Client

generate-client-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating client PKI resources"
	@([ '${OPENSSL_KEYALG_TYPE}' != '${OPENSSL_KEYALG_EC_TYPE}' ] || [ -f ${OPENSSL_KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${OPENSSL_KEYALG_EC_CURVE} -out ${OPENSSL_KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} client-pki-creator --client-cert-filepath ${TRUST0_CLIENT__PKI_CERT_FILE} --client-key-filepath ${TRUST0_CLIENT__PKI_KEY_FILE} --ca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --ca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${OPENSSL_KEYALG_TYPE}:${OPENSSL_KEYALG_PARAMS} --auth-user-id ${TRUST0_CLIENT__PKI_SUBJ_USERID} --auth-platform ${TRUST0_CLIENT__PKI_SUBJ_PLATFORM} --subj-common-name ${TRUST0_CLIENT__PKI_SUBJ_COMMONNAME} --subj-country ${TRUST0_CLIENT__PKI_SUBJ_COUNTRY} --subj-state ${TRUST0_CLIENT__PKI_SUBJ_STATE} --subj-city ${TRUST0_CLIENT__PKI_SUBJ_CITY} --subj-company ${TRUST0_CLIENT__PKI_SUBJ_COMPANY} --subj-dept ${TRUST0_CLIENT__PKI_SUBJ_DEPT}
	@echo ""

# PKI Provider Targets - CRL

setup-crl-files:
	@echo "Creating certificate revocation list file"
	@echo -n '' > ${ROOT_CA__PKI_DATABASE_FILE}
	@echo '1000' > ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
	@touch ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -revoke ${TRUST0_CLIENT__PKI_CERT_FILE} -crl_reason keyCompromise -out ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -out ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
