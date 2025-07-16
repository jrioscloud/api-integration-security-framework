# API Security Policy for Third-Party Integrations
# This policy validates API configurations against enterprise security standards

package api.security

# Default deny - all API configurations must explicitly pass security checks
default allow = false

# Allow API configuration if all security requirements are met
allow {
    input.type == "api_configuration"
    secrets_management_compliant
    encryption_compliant
    authentication_compliant
    audit_logging_enabled
}

# Secrets Management Compliance
secrets_management_compliant {
    # All API keys must be stored in AWS Secrets Manager
    input.credentials.storage_type == "aws_secrets_manager"
    
    # Secrets must have automatic rotation enabled
    input.credentials.auto_rotation_enabled == true
    
    # Rotation interval must not exceed 90 days
    input.credentials.rotation_interval_days <= 90
}

# Encryption Compliance  
encryption_compliant {
    # All API communications must use TLS 1.2 or higher
    input.transport.tls_version >= "1.2"
    
    # Certificate validation must be enabled
    input.transport.verify_certificates == true
    
    # Data at rest must be encrypted
    input.storage.encryption_at_rest == true
}

# Authentication Compliance
authentication_compliant {
    # API must use strong authentication method
    input.authentication.method in ["oauth2", "jwt", "api_key_with_signature"]
    
    # Token expiration must be configured
    input.authentication.token_expiration_hours > 0
    input.authentication.token_expiration_hours <= 24
    
    # Multi-factor authentication required for admin operations
    admin_operations_require_mfa
}

admin_operations_require_mfa {
    not input.operations.admin_capabilities
}

admin_operations_require_mfa {
    input.operations.admin_capabilities == true
    input.authentication.mfa_required == true
}

# Audit Logging Requirements
audit_logging_enabled {
    # All API calls must be logged
    input.logging.api_calls_logged == true
    
    # Authentication events must be logged
    input.logging.auth_events_logged == true
    
    # Failed requests must be logged
    input.logging.failed_requests_logged == true
    
    # Logs must be retained for compliance period
    input.logging.retention_days >= 2555  # 7 years for HIPAA
}

# HIPAA Specific Requirements
hipaa_compliant {
    input.compliance.framework == "hipaa"
    
    # PHI protection requirements
    input.data_handling.phi_encryption == true
    input.data_handling.access_logging == true
    input.data_handling.minimum_necessary == true
    
    # Business Associate Agreement required
    input.legal.baa_signed == true
}

# SOC2 Specific Requirements  
soc2_compliant {
    input.compliance.framework == "soc2"
    
    # Security control requirements
    input.controls.access_control == true
    input.controls.change_management == true
    input.controls.vulnerability_management == true
    
    # Monitoring requirements
    input.monitoring.security_events == true
    input.monitoring.availability == true
    input.monitoring.processing_integrity == true
}

# Integration-Specific Policies
stripe_integration_policy {
    input.integration.name == "stripe"
    
    # PCI DSS requirements for payment processing
    input.compliance.pci_dss_level == "1"
    input.payment.card_data_encryption == true
    input.payment.tokenization_enabled == true
    
    # Webhook validation required
    input.webhooks.signature_validation == true
}

auth0_integration_policy {
    input.integration.name == "auth0"
    
    # Identity provider requirements
    input.identity.secure_token_service == true
    input.identity.session_management == true
    input.identity.password_policy_enforced == true
}

salesforce_integration_policy {
    input.integration.name == "salesforce"
    
    # CRM data protection requirements
    input.crm.data_classification == true
    input.crm.field_level_security == true
    input.crm.sharing_rules_defined == true
}

# Violation reporting
violations[msg] {
    not secrets_management_compliant
    msg := "Secrets management does not meet security standards"
}

violations[msg] {
    not encryption_compliant  
    msg := "Encryption configuration does not meet security standards"
}

violations[msg] {
    not authentication_compliant
    msg := "Authentication configuration does not meet security standards"
}

violations[msg] {
    not audit_logging_enabled
    msg := "Audit logging configuration does not meet compliance requirements"
}

violations[msg] {
    input.compliance.framework == "hipaa"
    not hipaa_compliant
    msg := "Configuration does not meet HIPAA compliance requirements"
}

violations[msg] {
    input.compliance.framework == "soc2"
    not soc2_compliant
    msg := "Configuration does not meet SOC2 compliance requirements"
}
