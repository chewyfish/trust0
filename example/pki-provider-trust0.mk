TRUST0_PKI_MANAGER_CMD=${PROJECT_DIR}/target/debug/trust0-pki-manager

# Params - CRL

CRLSUPPORT__PKI_CRL_NUMBER=0100
CRLSUPPORT__PKI_UPDATE_DATETIME=2024-01-01T00:00:00Z
CRLSUPPORT__PKI_NEXT_UPDATE_DATETIME=2050-01-01T00:00:00Z
CRLSUPPORT__PKI_CERT_REVOCATION_DATETIME=${CRLSUPPORT__PKI_UPDATE_DATETIME}
CRLSUPPORT__PKI_CERT_REVOCATION_REASON=key-compromise
CRLSUPPORT__PKI_CERT_REVOCATION_SERIAL_NUMS=${TRUST0_CLIENT__PKI_SERIAL_NUM}

# Params - Key Algorithm

TRUST0_KEYALG_TYPE=ecdsa-p256
#TRUST0_KEYALG_TYPE=ecdsa-p384
#TRUST0_KEYALG_TYPE=ed25519

# PKI Provider Targets - ROOT CA

generate-root-ca-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating root CA PKI resources"
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_PKI_MANAGER_CMD} root-ca-pki-creator --cert-file ${ROOT_CA__PKI_CERT_FILE} --key-file ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${TRUST0_KEYALG_TYPE} --validity-not-after ${ROOT_CA__PKI_VALID_NOT_AFTER} --subject-common-name ${ROOT_CA__PKI_SUBJ_COMMONNAME} --subject-organization ${ROOT_CA__PKI_SUBJ_COMPANY} --subject-country ${ROOT_CA__PKI_SUBJ_COUNTRY}
	@echo ""

# PKI Provider Targets - Trust Gateway

generate-gateway-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating gateway PKI resources"
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_PKI_MANAGER_CMD} gateway-pki-creator --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --rootca-cert-file ${ROOT_CA__PKI_CERT_FILE} --rootca-key-file ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${TRUST0_KEYALG_TYPE} --serial-number ${TRUST0_GATEWAY__PKI_SERIAL_NUM} --validity-not-after ${TRUST0_GATEWAY__PKI_VALID_NOT_AFTER} --subject-common-name ${TRUST0_GATEWAY__PKI_SUBJ_COMMONNAME} --subject-organization ${TRUST0_GATEWAY__PKI_SUBJ_COMPANY} --subject-country ${TRUST0_GATEWAY__PKI_SUBJ_COUNTRY} --san-dns-names ${TRUST0_GATEWAY__PKI_HOST_DNS1},${TRUST0_GATEWAY__PKI_HOST_DNS2}
	@echo ""

# PKI Provider Targets - Trust Client

generate-client-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating client PKI resources"
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_PKI_MANAGER_CMD} client-pki-creator --cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --rootca-cert-file ${ROOT_CA__PKI_CERT_FILE} --rootca-key-file ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${TRUST0_KEYALG_TYPE} --serial-number ${TRUST0_CLIENT__PKI_SERIAL_NUM} --validity-not-after ${TRUST0_CLIENT__PKI_VALID_NOT_AFTER} --auth-user-id ${TRUST0_CLIENT__PKI_SUBJ_USERID} --auth-platform ${TRUST0_CLIENT__PKI_SUBJ_PLATFORM} --subject-common-name ${TRUST0_CLIENT__PKI_SUBJ_COMMONNAME} --subject-organization ${TRUST0_CLIENT__PKI_SUBJ_COMPANY} --subject-country ${TRUST0_CLIENT__PKI_SUBJ_COUNTRY}
	@echo ""

# PKI Provider Targets - CRL

setup-crl-files:
	@echo "Creating certificate revocation list file"
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
	@touch ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_PKI_MANAGER_CMD} cert-revocation-list-creator --file ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE} --rootca-cert-file ${ROOT_CA__PKI_CERT_FILE} --rootca-key-file ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${TRUST0_KEYALG_TYPE} --crl-number ${CRLSUPPORT__PKI_CRL_NUMBER} --update-datetime ${CRLSUPPORT__PKI_UPDATE_DATETIME} --next-update-datetime ${CRLSUPPORT__PKI_NEXT_UPDATE_DATETIME} --signature-algorithm ${TRUST0_KEYALG_TYPE} --cert-revocation-datetime ${CRLSUPPORT__PKI_CERT_REVOCATION_DATETIME} --cert-revocation-reason ${CRLSUPPORT__PKI_CERT_REVOCATION_REASON} --cert-revocation-serial-nums ${CRLSUPPORT__PKI_CERT_REVOCATION_SERIAL_NUMS}
	@echo ""
