# API Documentation: [Service Name]

## Overview

[Brief description of the API and its purpose]

**Base URL:** `https://api.example.com/v1`

**Authentication:** [Bearer Token | API Key | OAuth 2.0]

## Endpoints

### [Resource Name]

#### List [Resources]

```http
GET /resources
```

**Description:** [What this endpoint does]

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | integer | No | 1 | Page number |
| page_size | integer | No | 20 | Items per page (max 100) |
| sort | string | No | created_at | Sort field |
| order | string | No | desc | Sort order (asc, desc) |
| filter | string | No | - | Filter expression |

**Response:**

```json
{
  "data": [
    {
      "id": "string",
      "name": "string",
      "created_at": "2024-01-15T00:00:00Z",
      "updated_at": "2024-01-15T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid request parameters |
| 401 | Unauthorized |
| 500 | Internal server error |

---

#### Get [Resource]

```http
GET /resources/{id}
```

**Description:** [What this endpoint does]

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| id | string | Resource ID |

**Response:**

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "created_at": "2024-01-15T00:00:00Z",
  "updated_at": "2024-01-15T00:00:00Z"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |
| 404 | Resource not found |
| 401 | Unauthorized |

---

#### Create [Resource]

```http
POST /resources
```

**Description:** [What this endpoint does]

**Request Body:**

```json
{
  "name": "string",
  "description": "string"
}
```

**Response:**

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "created_at": "2024-01-15T00:00:00Z"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 201 | Created successfully |
| 400 | Invalid request body |
| 401 | Unauthorized |
| 409 | Conflict (resource already exists) |

---

#### Update [Resource]

```http
PATCH /resources/{id}
```

**Description:** [What this endpoint does]

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| id | string | Resource ID |

**Request Body:**

```json
{
  "name": "string",
  "description": "string"
}
```

**Response:**

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "updated_at": "2024-01-15T00:00:00Z"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Updated successfully |
| 400 | Invalid request body |
| 404 | Resource not found |
| 401 | Unauthorized |

---

#### Delete [Resource]

```http
DELETE /resources/{id}
```

**Description:** [What this endpoint does]

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| id | string | Resource ID |

**Response:**

```json
{
  "message": "Resource deleted successfully"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Deleted successfully |
| 404 | Resource not found |
| 401 | Unauthorized |

---

## Error Response Format

All error responses follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional error details"
    }
  },
  "request_id": "uuid"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| VALIDATION_ERROR | 400 | Request validation failed |
| NOT_FOUND | 404 | Resource not found |
| UNAUTHORIZED | 401 | Authentication required |
| FORBIDDEN | 403 | Insufficient permissions |
| CONFLICT | 409 | Resource conflict |
| RATE_LIMITED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Internal server error |

## Rate Limiting

- **Rate Limit:** 1000 requests per minute
- **Headers:**
  - `X-RateLimit-Limit`: Maximum requests per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Unix timestamp when the limit resets

## Webhooks

[If applicable, describe webhook functionality]

### Event Types

| Event | Description |
|-------|-------------|
| resource.created | Fired when a resource is created |
| resource.updated | Fired when a resource is updated |
| resource.deleted | Fired when a resource is deleted |

### Webhook Payload

```json
{
  "event": "resource.created",
  "timestamp": "2024-01-15T00:00:00Z",
  "data": {
    "id": "string",
    "name": "string"
  }
}
```

## SDK Examples

### cURL

```bash
curl -X GET "https://api.example.com/v1/resources" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

### Python

```python
import httpx

client = httpx.Client(
    base_url="https://api.example.com/v1",
    headers={"Authorization": "Bearer YOUR_TOKEN"}
)

response = client.get("/resources")
data = response.json()
```

### Go

```go
req, _ := http.NewRequest("GET", "https://api.example.com/v1/resources", nil)
req.Header.Set("Authorization", "Bearer YOUR_TOKEN")

client := &http.Client{}
resp, _ := client.Do(req)
```

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release |
