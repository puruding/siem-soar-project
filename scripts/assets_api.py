#!/usr/bin/env python3
"""
Simple Assets API Server
Serves asset data from PostgreSQL for the frontend
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
import os
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(title="SIEM Assets API")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "database": os.getenv("DB_NAME", "siem_soar"),
    "user": os.getenv("DB_USER", "siem"),
    "password": os.getenv("DB_PASSWORD", "siem_password"),
}

class Asset(BaseModel):
    id: str
    asset_id: str
    display_name: Optional[str]
    hostname: Optional[str]
    asset_type: str
    ip_addresses: List[str]
    criticality: str
    status: str
    os_family: Optional[str]
    os_name: Optional[str]
    owner: Optional[str]
    department: Optional[str]
    location: Optional[str]
    tags: List[str]
    last_seen_at: Optional[datetime]
    created_at: Optional[datetime]
    # Product/data_source relationship
    data_source_id: Optional[str] = None
    product_name: Optional[str] = None
    vendor_name: Optional[str] = None
    parser_type: Optional[str] = None

class Product(BaseModel):
    id: str
    name: str
    vendor: Optional[str]
    product: Optional[str]
    version: Optional[str]
    source_type: str
    status: str
    # Parser info (embedded in data_sources)
    parser_type: Optional[str] = None
    parser_config: Optional[dict] = None
    field_mapping: Optional[dict] = None

class ProductUpdate(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    source_type: Optional[str] = None
    status: Optional[str] = None
    parser_type: Optional[str] = None
    parser_config: Optional[dict] = None

class Parser(BaseModel):
    id: str
    data_source_id: str
    name: str
    parser_type: str
    pattern: Optional[str] = None
    parser_config: Optional[dict] = None
    field_mapping: Optional[dict] = None
    sample_logs: Optional[List[str]] = None
    status: str
    version: int
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    # Joined fields
    product_name: Optional[str] = None
    vendor_name: Optional[str] = None

class ParserCreate(BaseModel):
    data_source_id: str
    name: str
    parser_type: str
    pattern: Optional[str] = None
    parser_config: Optional[dict] = None
    field_mapping: Optional[dict] = None
    sample_logs: Optional[List[str]] = None
    status: str = 'ACTIVE'

class ParserUpdate(BaseModel):
    name: Optional[str] = None
    parser_type: Optional[str] = None
    pattern: Optional[str] = None
    parser_config: Optional[dict] = None
    field_mapping: Optional[dict] = None
    sample_logs: Optional[List[str]] = None
    status: Optional[str] = None

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/v1/assets", response_model=List[Asset])
def list_assets(
    asset_type: Optional[str] = None,
    status: Optional[str] = None,
    criticality: Optional[str] = None,
    search: Optional[str] = None,
):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            query = """
                SELECT
                    a.id::text,
                    a.asset_id,
                    a.display_name,
                    a.hostname,
                    a.asset_type,
                    COALESCE(
                        array_agg(DISTINCT ip::text) FILTER (WHERE ip IS NOT NULL),
                        ARRAY[]::text[]
                    ) as ip_addresses,
                    a.criticality::text,
                    a.status::text,
                    a.os_family,
                    a.os_name,
                    a.owner,
                    a.department,
                    a.location,
                    COALESCE(a.tags, ARRAY[]::text[]) as tags,
                    a.last_seen_at,
                    a.created_at,
                    a.data_source_id::text,
                    ds.name as product_name,
                    ds.vendor as vendor_name,
                    ds.parser_type
                FROM meta.assets a
                LEFT JOIN meta.data_sources ds ON a.data_source_id = ds.id,
                LATERAL unnest(COALESCE(a.ip_addresses, ARRAY[]::inet[])) as ip
                WHERE 1=1
            """
            params = []

            if asset_type and asset_type != 'all':
                query += " AND a.asset_type = %s"
                params.append(asset_type)

            if status and status != 'all':
                query += " AND a.status = %s"
                params.append(status.upper())

            if criticality and criticality != 'all':
                query += " AND a.criticality = %s"
                params.append(criticality.upper())

            if search:
                query += " AND (a.display_name ILIKE %s OR a.hostname ILIKE %s OR a.asset_id ILIKE %s)"
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern, search_pattern])

            query += """
                GROUP BY a.id, a.asset_id, a.display_name, a.hostname, a.asset_type,
                         a.criticality, a.status, a.os_family, a.os_name, a.owner,
                         a.department, a.location, a.tags, a.last_seen_at, a.created_at,
                         a.data_source_id, ds.name, ds.vendor, ds.parser_type
                ORDER BY a.display_name
            """

            cur.execute(query, params)
            rows = cur.fetchall()

            return [Asset(**row) for row in rows]
    finally:
        conn.close()

@app.get("/api/v1/assets/{asset_id}", response_model=Asset)
def get_asset(asset_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    a.id::text,
                    a.asset_id,
                    a.display_name,
                    a.hostname,
                    a.asset_type,
                    COALESCE(
                        array_agg(DISTINCT ip::text) FILTER (WHERE ip IS NOT NULL),
                        ARRAY[]::text[]
                    ) as ip_addresses,
                    a.criticality::text,
                    a.status::text,
                    a.os_family,
                    a.os_name,
                    a.owner,
                    a.department,
                    a.location,
                    COALESCE(a.tags, ARRAY[]::text[]) as tags,
                    a.last_seen_at,
                    a.created_at,
                    a.data_source_id::text,
                    ds.name as product_name,
                    ds.vendor as vendor_name,
                    ds.parser_type
                FROM meta.assets a
                LEFT JOIN meta.data_sources ds ON a.data_source_id = ds.id,
                LATERAL unnest(COALESCE(a.ip_addresses, ARRAY[]::inet[])) as ip
                WHERE a.id::text = %s OR a.asset_id = %s
                GROUP BY a.id, a.asset_id, a.display_name, a.hostname, a.asset_type,
                         a.criticality, a.status, a.os_family, a.os_name, a.owner,
                         a.department, a.location, a.tags, a.last_seen_at, a.created_at,
                         a.data_source_id, ds.name, ds.vendor, ds.parser_type
            """, (asset_id, asset_id))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Asset not found")

            return Asset(**row)
    finally:
        conn.close()

@app.get("/api/v1/products", response_model=List[Product])
def list_products(
    source_type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            query = """
                SELECT
                    id::text,
                    name,
                    vendor,
                    product,
                    version,
                    source_type,
                    status::text,
                    parser_type,
                    parser_config,
                    field_mapping
                FROM meta.data_sources
                WHERE 1=1
            """
            params = []

            if source_type and source_type != 'all':
                query += " AND source_type = %s"
                params.append(source_type)

            if status and status != 'all':
                query += " AND status = %s"
                params.append(status.upper())

            if search:
                query += " AND (name ILIKE %s OR vendor ILIKE %s OR product ILIKE %s)"
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern, search_pattern])

            query += " ORDER BY name"

            cur.execute(query, params)
            rows = cur.fetchall()

            return [Product(**row) for row in rows]
    finally:
        conn.close()

@app.get("/api/v1/products/{product_id}", response_model=Product)
def get_product(product_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    id::text,
                    name,
                    vendor,
                    product,
                    version,
                    source_type,
                    status::text,
                    parser_type,
                    parser_config,
                    field_mapping
                FROM meta.data_sources
                WHERE id::text = %s
            """, (product_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Product not found")

            return Product(**row)
    finally:
        conn.close()

@app.patch("/api/v1/products/{product_id}", response_model=Product)
def update_product(product_id: str, updates: ProductUpdate):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Build dynamic SET clause from provided fields only
            set_clauses = []
            params = []

            if updates.vendor is not None:
                set_clauses.append("vendor = %s")
                params.append(updates.vendor)
            if updates.product is not None:
                set_clauses.append("product = %s")
                params.append(updates.product)
            if updates.version is not None:
                set_clauses.append("version = %s")
                params.append(updates.version)
            if updates.source_type is not None:
                set_clauses.append("source_type = %s")
                params.append(updates.source_type)
            if updates.status is not None:
                set_clauses.append("status = %s")
                params.append(updates.status.upper())
            if updates.parser_type is not None:
                set_clauses.append("parser_type = %s")
                params.append(updates.parser_type)
            elif 'parser_type' in updates.model_fields_set:
                # Explicitly set to null
                set_clauses.append("parser_type = NULL")
            if updates.parser_config is not None:
                set_clauses.append("parser_config = %s")
                params.append(psycopg2.extras.Json(updates.parser_config))
            elif 'parser_config' in updates.model_fields_set:
                set_clauses.append("parser_config = NULL")

            if not set_clauses:
                raise HTTPException(status_code=400, detail="No fields to update")

            set_clauses.append("updated_at = NOW()")
            params.append(product_id)

            query = f"""
                UPDATE meta.data_sources
                SET {', '.join(set_clauses)}
                WHERE id::text = %s
                RETURNING
                    id::text,
                    name,
                    vendor,
                    product,
                    version,
                    source_type,
                    status::text,
                    parser_type,
                    parser_config,
                    field_mapping
            """
            cur.execute(query, params)
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Product not found")

            conn.commit()
            return Product(**row)
    finally:
        conn.close()

TENANT_ID = '11111111-1111-1111-1111-111111111111'

def _parser_select() -> str:
    return """
        SELECT
            p.id::text,
            p.data_source_id::text,
            p.name,
            p.parser_type,
            p.pattern,
            p.parser_config,
            p.field_mapping,
            p.sample_logs,
            p.status,
            p.version,
            p.created_at::text,
            p.updated_at::text,
            ds.name as product_name,
            ds.vendor as vendor_name
        FROM meta.parsers p
        LEFT JOIN meta.data_sources ds ON p.data_source_id = ds.id
    """

@app.get("/api/v1/parsers", response_model=List[Parser])
def list_parsers(
    data_source_id: Optional[str] = None,
    parser_type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            query = _parser_select() + " WHERE p.tenant_id = %s"
            params = [TENANT_ID]

            if data_source_id:
                query += " AND p.data_source_id::text = %s"
                params.append(data_source_id)

            if parser_type and parser_type != 'all':
                query += " AND p.parser_type = %s"
                params.append(parser_type)

            if status and status != 'all':
                query += " AND p.status = %s"
                params.append(status.upper())

            if search:
                query += " AND (p.name ILIKE %s OR p.parser_type ILIKE %s OR ds.name ILIKE %s)"
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern, search_pattern])

            query += " ORDER BY p.name"

            cur.execute(query, params)
            rows = cur.fetchall()

            return [Parser(**row) for row in rows]
    finally:
        conn.close()

@app.get("/api/v1/parsers/{parser_id}", response_model=Parser)
def get_parser(parser_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                _parser_select() + " WHERE p.id::text = %s AND p.tenant_id = %s",
                (parser_id, TENANT_ID)
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Parser not found")

            return Parser(**row)
    finally:
        conn.close()

@app.post("/api/v1/parsers", response_model=Parser, status_code=201)
def create_parser(parser: ParserCreate):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO meta.parsers
                    (tenant_id, data_source_id, name, parser_type, pattern,
                     parser_config, field_mapping, sample_logs, status)
                VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id::text, data_source_id::text, name, parser_type, pattern,
                          parser_config, field_mapping, sample_logs, status, version,
                          created_at::text, updated_at::text
            """, (
                TENANT_ID,
                parser.data_source_id,
                parser.name,
                parser.parser_type,
                parser.pattern,
                psycopg2.extras.Json(parser.parser_config or {}),
                psycopg2.extras.Json(parser.field_mapping or {}),
                parser.sample_logs,
                parser.status.upper(),
            ))
            row = dict(cur.fetchone())
            conn.commit()

            # Fetch joined data
            cur.execute(
                _parser_select() + " WHERE p.id::text = %s",
                (row['id'],)
            )
            full_row = cur.fetchone()
            return Parser(**full_row)
    finally:
        conn.close()

@app.patch("/api/v1/parsers/{parser_id}", response_model=Parser)
def update_parser(parser_id: str, updates: ParserUpdate):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            set_clauses = []
            params = []

            if updates.name is not None:
                set_clauses.append("name = %s")
                params.append(updates.name)
            if updates.parser_type is not None:
                set_clauses.append("parser_type = %s")
                params.append(updates.parser_type)
            if updates.pattern is not None:
                set_clauses.append("pattern = %s")
                params.append(updates.pattern)
            if updates.parser_config is not None:
                set_clauses.append("parser_config = %s")
                params.append(psycopg2.extras.Json(updates.parser_config))
            if updates.field_mapping is not None:
                set_clauses.append("field_mapping = %s")
                params.append(psycopg2.extras.Json(updates.field_mapping))
            if updates.sample_logs is not None:
                set_clauses.append("sample_logs = %s")
                params.append(updates.sample_logs)
            if updates.status is not None:
                set_clauses.append("status = %s")
                params.append(updates.status.upper())

            if not set_clauses:
                raise HTTPException(status_code=400, detail="No fields to update")

            set_clauses.append("version = version + 1")
            set_clauses.append("updated_at = NOW()")
            params.extend([parser_id, TENANT_ID])

            cur.execute(
                f"UPDATE meta.parsers SET {', '.join(set_clauses)} WHERE id::text = %s AND tenant_id = %s",
                params
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Parser not found")

            conn.commit()

            cur.execute(
                _parser_select() + " WHERE p.id::text = %s",
                (parser_id,)
            )
            row = cur.fetchone()
            return Parser(**row)
    finally:
        conn.close()

@app.delete("/api/v1/parsers/{parser_id}", status_code=204)
def delete_parser(parser_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM meta.parsers WHERE id::text = %s AND tenant_id = %s",
                (parser_id, TENANT_ID)
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Parser not found")
            conn.commit()
    finally:
        conn.close()

@app.get("/api/v1/products/{product_id}/parsers", response_model=List[Parser])
def get_product_parsers(product_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                _parser_select() + " WHERE p.data_source_id::text = %s AND p.tenant_id = %s ORDER BY p.name",
                (product_id, TENANT_ID)
            )
            rows = cur.fetchall()
            return [Parser(**row) for row in rows]
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8088)
