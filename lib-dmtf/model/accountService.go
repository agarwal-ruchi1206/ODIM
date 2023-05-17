//(C) Copyright [2022] Hewlett Packard Enterprise Development LP
//
//Licensed under the Apache License, Version 2.0 (the "License"); you may
//not use this file except in compliance with the License. You may obtain
//a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//License for the specific language governing permissions and limitations
// under the License.

package model

type RestrictedPrivileges string

type SupportedAccountTypes string

type LocalAccountAuth string

type AuthenticationTypes string

type CertificateMappingAttribute string

type AccountProviderType string

type Mode string

type PrivilegeType string

type PasswordExchangeProtocols string

const (
	RestrictedPrivilegesLogin                              RestrictedPrivileges = "Login"
	RestrictedPrivilegesConfigureManager                   RestrictedPrivileges = "ConfigureManager"
	RestrictedPrivilegesConfigureUsers                     RestrictedPrivileges = "ConfigureUsers"
	RestrictedPrivilegesConfigureSelf                      RestrictedPrivileges = "ConfigureSelf"
	RestrictedPrivilegesConfigureComponents                RestrictedPrivileges = "ConfigureComponents"
	RestrictedPrivilegesNoAuth                             RestrictedPrivileges = "NoAuth"
	RestrictedPrivilegesConfigureCompositionInfrastructure RestrictedPrivileges = "ConfigureCompositionInfrastructure"
	RestrictedPrivilegesAdministrateSystems                RestrictedPrivileges = "AdministrateSystems"
	RestrictedPrivilegesOperateSystems                     RestrictedPrivileges = "OperateSystems"
	RestrictedPrivilegesAdministrateStorage                RestrictedPrivileges = "AdministrateStorage"
	RestrictedPrivilegesOperateStorageBackup               RestrictedPrivileges = "OperateStorageBackup"

	SupportedAccountTypesRedfish        SupportedAccountTypes = "Redfish"
	SupportedAccountTypesSNMP           SupportedAccountTypes = "SNMP"
	SupportedAccountTypesOEM            SupportedAccountTypes = "OEM"
	SupportedAccountTypeHostConsole     SupportedAccountTypes = "HostConsole"
	SupportedAccountTypesManagerConsole SupportedAccountTypes = "ManagerConsole"
	SupportedAccountTypesIPMI           SupportedAccountTypes = "IPMI"
	SupportedAccountTypesKVMIP          SupportedAccountTypes = "KVMIP"
	SupportedAccountTypesVirtualMedia   SupportedAccountTypes = "VirtualMedia"
	SupportedAccountTypesWebUI          SupportedAccountTypes = "WebUI"

	LocalAccountAuthEnabled    LocalAccountAuth = "Enabled"
	LocalAccountAuthDisabled   LocalAccountAuth = "Disabled"
	LocalAccountAuthFallback   LocalAccountAuth = "Fallback"
	LocalAccountAuthLocalFirst LocalAccountAuth = "LocalFirst"

	AuthenticationTypesToken               AuthenticationTypes = "Token"
	AuthenticationTypesKerberosKeytab      AuthenticationTypes = "KerberosKeytab"
	AuthenticationTypesUsernameAndPassword AuthenticationTypes = "UsernameAndPassword"
	AuthenticationTypesOEM                 AuthenticationTypes = "OEM"

	CertificateMappingAttributeWhole             CertificateMappingAttribute = "Whole"
	CertificateMappingAttributeCommonName        CertificateMappingAttribute = "CommonName"
	CertificateMappingAttributeUserPrincipalName CertificateMappingAttribute = "UserPrincipalName"

	AccountProviderTypeRedfishService         AccountProviderType = "RedfishService"
	AccountProviderTypeActiveDirectoryService AccountProviderType = "ActiveDirectoryService"
	AccountProviderTypeLDAPService            AccountProviderType = "LDAPService"
	AccountProviderTypeOEM                    AccountProviderType = "OEM"
	AccountProviderTypeTACACSplus             AccountProviderType = "TACACSplus"
	AccountProviderTypeOAuth2                 AccountProviderType = "OAuth2"

	ModeDiscovery Mode = "Discovery"
	ModeOffline   Mode = "Offline"

	PasswordExchangeProtocolsASCII    PasswordExchangeProtocols = "ASCII"
	PasswordExchangeProtocolsPAP      PasswordExchangeProtocols = "PAP"
	PasswordExchangeProtocolsCHAP     PasswordExchangeProtocols = "CHAP"
	PasswordExchangeProtocolsMSCHAPv1 PasswordExchangeProtocols = "MSCHAPv1"
	PasswordExchangeProtocolsMSCHAPv2 PasswordExchangeProtocols = "MSCHAPv2"

	PrivilegeTypeLogin                              PrivilegeType = "Login"
	PrivilegeTypeConfigureManager                   PrivilegeType = "ConfigureManager"
	PrivilegeTypeConfigureUsers                     PrivilegeType = "ConfigureUsers"
	PrivilegeTypeConfigureSelf                      PrivilegeType = "ConfigureSelf"
	PrivilegeTypeConfigureComponents                PrivilegeType = "ConfigureComponents"
	PrivilegeTypeNoAuth                             PrivilegeType = "NoAuth"
	PrivilegeTypeConfigureCompositionInfrastructure PrivilegeType = "ConfigureCompositionInfrastructure"
	PrivilegeTypeAdministrateSystems                PrivilegeType = "AdministrateSystems"
	PrivilegeTypeOperateSystems                     PrivilegeType = "OperateSystems"
	PrivilegeTypeAdministrateStorage                PrivilegeType = "AdministrateStorage"
	PrivilegeTypeOperateStorageBackup               PrivilegeType = "OperateStorageBackup"
)

// AccountService the supported properties,
// this structure should be updated once ODIMRA supports more properties
type AccountService struct {
	ODataContext                       string                              `json:"@odata.context,omitempty"`
	ODataEtag                          string                              `json:"@odata.etag,omitempty"`
	ODataID                            string                              `json:"@odata.id"`
	ODataType                          string                              `json:"@odata.type"`
	AccountLockoutCounterResetAfter    int                                 `json:"AccountLockoutCounterResetAfter,omitempty"`
	AccountLockoutCounterResetEnabled  bool                                `json:"AccountLockoutCounterResetEnabled,omitempty"`
	AccountLockoutDuration             int                                 `json:"AccountLockoutDuration,omitempty"`
	AccountLockoutThreshold            int                                 `json:"AccountLockoutThreshold,omitempty"`
	Actions                            *OemActions                         `json:"Actions,omitempty"`
	ActiveDirectory                    *ExternalAccountProvider            `json:"ActiveDirectory,omitempty"`
	AdditionalExternalAccountProviders *AdditionalExternalAccountProviders `json:"AdditionalExternalAccountProviders,omitempty"`
	AuthFailureLoggingThreshold        int                                 `json:"AuthFailureLoggingThreshold,omitempty"`
	LDAP                               *ExternalAccountProvider            `json:"LDAP,omitempty"`
	MultiFactorAuth                    *MultiFactorAuth                    `json:"MultiFactorAuth,omitempty"`
	OAuth2                             *ExternalAccountProvider            `json:"OAuth2,omitempty"`
	Oem                                *Oem                                `json:"Oem,omitempty"`
	PrivilegeMap                       *PrivilegeMap                       `json:"PrivilegeMap,omitempty"` //HELP
	RestrictedOemPrivileges            []string                            `json:"RestrictedOemPrivileges,omitempty"`
	RestrictedPrivileges               []string                            `json:"RestrictedPrivileges,omitempty"`  //enum
	SupportedAccountTypes              []string                            `json:"SupportedAccountTypes,omitempty"` //enum
	SupportedOEMAccountTypes           []string                            `json:"SupportedOEMAccountTypes,omitempty"`
	TACACSplus                         *ExternalAccountProvider            `json:"TACACSplus,omitempty"`
	ID                                 string                              `json:"Id"`
	Name                               string                              `json:"Name"`
	Description                        string                              `json:"Description,omitempty"`
	Status                             Status                              `json:"Status,omitempty"`
	Accounts                           Link                                `json:"Accounts,omitempty"`
	Roles                              Link                                `json:"Roles,omitempty"`
	MinPasswordLength                  int                                 `json:"MinPasswordLength,omitempty"`
	MaxPasswordLength                  int                                 `json:"MaxPasswordLength,omitempty"`
	PasswordExpirationDays             int                                 `json:"PasswordExpirationDays,omitempty"`
	ServiceEnabled                     bool                                `json:"ServiceEnabled,omitempty"`
	LocalAccountAuth                   string                              `json:"LocalAccountAuth,omitempty"` //enum
}

type Authentication struct {
	AuthenticationType string `json:"AuthenticationType,omitempty"` //enum
	EncryptionKey      string `json:"EncryptionKey,omitempty"`
	EncryptionKeySet   bool   `json:"EncryptionKeySet,omitempty"`
	KerberosKeytab     string `json:"KerberosKeytab,omitempty"`
	Oem                *Oem   `json:"Oem,omitempty"`
	Password           string `json:"Password,omitempty"`
	Username           string `json:"Username,omitempty"`
}
type ClientCertificate struct {
	CertificateMappingAttribute     string       `json:"CertificateMappingAttribute,omitempty"` //enum
	Certificates                    Certificates `json:"Certificates,omitempty"`
	Enabled                         bool         `json:"Enabled,omitempty"`
	RespondToUnauthenticatedClients bool         `json:"RespondToUnauthenticatedClients,omitempty"`
}

type ExternalAccountProvider struct {
	AccountProviderType string             `json:"AccountProviderType,omitempty"` //enum
	Authentication      *Authentication    `json:"Authentication,omitempty"`
	Certificates        *Certificates      `json:"Certificates,omitempty"`
	LDAPService         *LDAPService       `json:"LDAPService,omitempty"`
	OAuth2Service       *OAuth2Service     `json:"OAuth2Service,omitempty"`
	PasswordSet         bool               `json:"PasswordSet,omitempty"`
	Priority            int                `json:"Priority"`
	RemoteRoleMapping   *RoleMapping       `json:"RemoteRoleMapping"`
	ServiceAddresses    []string           `json:"ServiceAddresses,omitempty"`
	ServiceEnabled      bool               `json:"ServiceEnabled,omitempty"`
	TACACSplusService   *TACACSplusService `json:"TACACSplusService,omitempty"`
}

type GoogleAuthenticator struct {
	Enabled      bool   `json:"Enabled,omitempty"`
	SecretKey    string `json:"SecretKey,omitempty"`
	SecretKeySet bool   `json:"SecretKeySet,omitempty"`
}

type LDAPSearchSettings struct {
	BaseDistinguishedNames []string `json:"BaseDistinguishedNames,omitempty"`
	GroupNameAttribute     string   `json:"GroupNameAttribute,omitempty"`
	GroupsAttribute        string   `json:"GroupsAttribute,omitempty"`
	SSHKeyAttribute        string   `json:"SSHKeyAttribute,omitempty"`
	UsernameAttribute      string   `json:"UsernameAttribute,omitempty"`
}

type LDAPService struct {
	Oem            *Oem                `json:"Oem,omitempty"`
	SearchSettings *LDAPSearchSettings `json:"SearchSettings,omitempty"`
}

type MFABypass struct {
	BypassTypes []string `json:"BypassTypes,omitempty"`
}

type MicrosoftAuthenticator struct {
	Enabled      bool   `json:"Enabled,omitempty"`
	SecretKey    string `json:"SecretKey,omitempty"`
	SecretKeySet bool   `json:"SecretKeySet,omitempty"`
}

type MultiFactorAuth struct {
	ClientCertificate      *ClientCertificate      `json:"ClientCertificate,omitempty"`
	GoogleAuthenticator    *GoogleAuthenticator    `json:"GoogleAuthenticator,omitempty"`
	MicrosoftAuthenticator *MicrosoftAuthenticator `json:"MicrosoftAuthenticator,omitempty"`
	SecurID                *SecurID                `json:"SecurID,omitempty"`
}

type OAuth2Service struct {
	Audience                []string `json:"Audience,omitempty"`
	Issuer                  string   `json:"Issuer,omitempty"`
	Mode                    string   `json:"Mode,omitempty"` //enum
	OAuthServiceSigningKeys string   `json:"OAuthServiceSigningKeys,omitempty"`
}

type SecurID struct {
	Certificates    *Certificates `json:"Certificates,omitempty"`
	ClientId        string        `json:"ClientId,omitempty"`
	ClientSecret    string        `json:"ClientSecret,omitempty"`
	ClientSecretSet bool          `json:"ClientSecretSet,omitempty"`
	Enabled         bool          `json:"Enabled,omitempty"`
	ServerURI       string        `json:"ServerURI,omitempty"`
}

type RoleMapping struct {
	LocalRole   string     `json:"LocalRole,omitempty"`
	MFABypass   *MFABypass `json:"MFABypass,omitempty"`
	Oem         *Oem       `json:"Oem,omitempty"`
	RemoteGroup string     `json:"RemoteGroup,omitempty"`
	RemoteUser  string     `json:"RemoteUser,omitempty"`
}

type TACACSplusService struct {
	PasswordExchangeProtocols string `json:"PasswordExchangeProtocols,omitempty"` //enum
	PrivilegeLevelArgument    string `json:"PrivilegeLevelArgument,omitempty"`
}
type AdditionalExternalAccountProviders struct {
	ODataContext         string   `json:"@odata.context,omitempty"`
	ODataEtag            string   `json:"@odata.etag,omitempty"`
	ODataID              string   `json:"@odata.id"`
	ODataType            string   `json:"@odata.type"`
	Description          string   `json:"Description,omitempty"`
	Members              []string `json:"Members"`
	MembersODataCount    int      `json:"Members@odata.count"`
	MembersODataNextLink string   `json:"Members@odata.nextLink,omitempty"`
	Name                 string   `json:"Name"`
	Oem                  *Oem     `json:"Oem,omitempty"`
}
type PrivilegeMap struct {
	ODataType         string      `json:"@odata.type"`
	Actions           *OemActions `json:"Actions,omitempty"`
	Description       string      `json:"Description,omitempty"`
	ID                string      `json:"Id"`
	Mapping           *Mapping    `json:"Mapping,omitempty"`
	Name              string      `json:"Name"`
	OEMPrivilegesUsed []string    `json:"OEMPrivilegesUsed,omitempty"`
	Oem               Oem         `json:"Oem,omitempty"`
	PrivilegesUsed    []string    `json:"PrivilegesUsed,omitempty"` //enum
}

type Mapping struct {
	Entity               string              `json:"Entity,omitempty"`
	OperationMap         OperationMap        `json:"OperationMap,omitempty"`
	PropertyOverrides    Target_PrivilegeMap `json:"PropertyOverrides,omitempty"`
	ResourceURIOverrides Target_PrivilegeMap `json:"ResourceURIOverrides,omitempty"`
	SubordinateOverrides Target_PrivilegeMap `json:"SubordinateOverrides,omitempty"`
}
type Target_PrivilegeMap struct {
	OperationMap OperationMap `json:"OperationMap,omitempty"`
	Targets      []string     `json:"Targets,omitempty"`
}
type OperationMap struct {
	DELETE OperationPrivilege `json:"DELETE,omitempty"`
	GET    OperationPrivilege `json:"GET,omitempty"`
	HEAD   OperationPrivilege `json:"HEAD,omitempty"`
	POST   OperationPrivilege `json:"POST,omitempty"`
	PUT    OperationPrivilege `json:"PUT,omitempty"`
	PATCH  OperationPrivilege `json:"PATCH,omitempty"`
}
type OperationPrivilege struct {
	Privilege []string `json:"Privilege,omitempty"`
}

// ManagerAccount the supported properties of manager account schema,
// this structure should be updated once ODIMRA supports more properties
type ManagerAccount struct {
	ODataContext           string       `json:"@odata.context,omitempty"`
	ODataEtag              string       `json:"@odata.etag,omitempty"`
	ODataID                string       `json:"@odata.id"`
	ODataType              string       `json:"@odata.type"`
	ID                     string       `json:"Id"`
	Name                   string       `json:"Name"`
	Description            string       `json:"Description,omitempty"`
	UserName               string       `json:"UserName,omitempty"`
	Password               string       `json:"Password,omitempty"`
	RoleID                 string       `json:"RoleId,omitempty"`
	Enabled                bool         `json:"Enabled,omitempty"`
	Locked                 bool         `json:"Locked,omitempty"`
	PasswordChangeRequired bool         `json:"PasswordChangeRequired,omitempty"`
	PasswordExpiration     string       `json:"PasswordExpiration,omitempty"`
	AccountExpiration      string       `json:"AccountExpiration,omitempty"`
	Links                  AccountLinks `json:"Links,omitempty"`
	AccountTypes           string       `json:"AccountTypes,omitempty"`
	Keys                   *Collection  `json:"Keys,omitempty"`
}

//AccountLinks struct definition
type AccountLinks struct {
	Role Link `json:"Role"`
}

// Role the supported properties of role schema,
// this structure should be updated once ODIMRA supports more properties
type Role struct {
	ODataContext       string   `json:"@odata.context,omitempty"`
	ODataEtag          string   `json:"@odata.etag,omitempty"`
	ODataID            string   `json:"@odata.id"`
	ODataType          string   `json:"@odata.type"`
	ID                 string   `json:"Id"`
	Name               string   `json:"Name"`
	Description        string   `json:"Description,omitempty"`
	AlternateRoleID    string   `json:"AlternateRoleId,omitempty"`
	AssignedPrivileges []string `json:"AssignedPrivileges,omitempty"`
	IsPredefined       bool     `json:"IsPredefined,omitempty"`
	Restricted         bool     `json:"Restricted,omitempty"`
	RoleID             string   `json:"RoleId,omitempty"`
}
