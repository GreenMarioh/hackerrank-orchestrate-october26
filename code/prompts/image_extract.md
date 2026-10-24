# Image Extraction Prompt

Extract structured JSON from the internal product/admin screenshot.
Identify all visible resources, customer identifiers, orders, support tickets, statuses, and configuration settings.

Return ONLY a valid JSON object with this exact schema:
```json
{
  "system_id": "account_service | search_service | integration_service | analytics_platform | export_service | support_platform | backup_service | security_service | identity_service | object_storage | marketing_platform",
  "records": [
    {
      "resource_id": "string (e.g. account_5762, search_428, data_flow_1121, etc.)",
      "user_id": "string | null",
      "email": "string | null",
      "phone": "string | null",
      "name": "string | null",
      "status": "string | null",
      "enabled": "boolean | null",
      "restore_allowed": "boolean | null",
      "details": "string | null"
    }
  ]
}
```
