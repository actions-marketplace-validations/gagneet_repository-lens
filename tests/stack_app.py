"""A small undocumented Next.js application used by the documentation and annotation tests.

No comments, no JSDoc, no markers: the shape an AI-generated application usually has.
It still holds the evidence the outputs are built from:

- `app/orders/page.tsx` calls `/api/orders` from an inline `onClick` callback and from a
  nested `load` function;
- `app/api/orders/route.ts` serves GET and POST through `lib/orders.ts` (PostgreSQL
  `orders`), and splices request input into SQL text (`SQL_INJECTION_RISK`);
- `app/api/orders/[orderId]/route.ts` names its parameter `orderId`;
- `app/api/reviews/route.ts` serves only GET from the MongoDB `reviews` collection, and
  `app/products/page.tsx` POSTs to it (`API_METHOD_MISMATCH`);
- `db/schema.sql` declares `customers` and `orders` with a foreign key.
"""
from __future__ import annotations

from pathlib import Path

FILES = {
    "package.json": '{"name": "shop-app", "private": true, "dependencies": '
                    '{"next": "15.0.0", "react": "19.0.0", "pg": "8.13.0", "mongodb": "6.10.0"}}\n',
    "lib/db.ts": 'import { Pool } from "pg";\n\nexport const pool = new Pool();\n',
    "lib/orders.ts": (
        'import { pool } from "./db";\n'
        "\n"
        "export async function listOrders() {\n"
        '  const { rows } = await pool.query("SELECT id, total, status FROM orders ORDER BY id LIMIT 50");\n'
        "  return rows;\n"
        "}\n"
        "\n"
        "export async function getOrder(orderId: string) {\n"
        '  const { rows } = await pool.query("SELECT id, total, status FROM orders WHERE id = $1", [orderId]);\n'
        "  return rows[0];\n"
        "}\n"
        "\n"
        "export async function createOrder(customerId: number, total: number) {\n"
        '  await pool.query("INSERT INTO orders (customer_id, total, status) VALUES ($1, $2, \'new\')", [customerId, total]);\n'
        "}\n"
    ),
    "app/api/orders/route.ts": (
        'import { pool } from "../../../lib/db";\n'
        'import { createOrder, listOrders } from "../../../lib/orders";\n'
        "\n"
        "export async function GET(request: Request) {\n"
        '  const status = new URL(request.url).searchParams.get("status");\n'
        "  if (status) {\n"
        "    const { rows } = await pool.query(`SELECT id, total FROM orders WHERE status = '${status}'`);\n"
        "    return Response.json(rows);\n"
        "  }\n"
        "  return Response.json(await listOrders());\n"
        "}\n"
        "\n"
        "export async function POST(request: Request) {\n"
        "  const body = await request.json();\n"
        "  await createOrder(Number(body.customerId), Number(body.total));\n"
        "  return Response.json({ ok: true }, { status: 201 });\n"
        "}\n"
    ),
    "app/api/orders/[orderId]/route.ts": (
        'import { getOrder } from "../../../../lib/orders";\n'
        "\n"
        "export async function GET(_request: Request, { params }: { params: { orderId: string } }) {\n"
        "  return Response.json(await getOrder(params.orderId));\n"
        "}\n"
    ),
    "app/api/reviews/route.ts": (
        'import { MongoClient } from "mongodb";\n'
        "\n"
        "const client = new MongoClient(process.env.MONGO_URL ?? \"mongodb://localhost:27017\");\n"
        "\n"
        "export async function GET() {\n"
        '  const db = client.db("shop");\n'
        '  const reviews = await db.collection("reviews").find({}).limit(20).toArray();\n'
        "  return Response.json(reviews);\n"
        "}\n"
    ),
    "app/orders/page.tsx": (
        '"use client";\n'
        'import { useState } from "react";\n'
        "\n"
        "export default function OrdersPage() {\n"
        "  const [orders, setOrders] = useState([]);\n"
        "  const load = async () => {\n"
        '    const response = await fetch("/api/orders");\n'
        "    setOrders(await response.json());\n"
        "  };\n"
        "  return (\n"
        "    <main>\n"
        "      <button onClick={load}>Load</button>\n"
        '      <button onClick={() => fetch("/api/orders", { method: "POST", body: JSON.stringify({ customerId: 1, total: 10 }) })}>\n'
        "        New order\n"
        "      </button>\n"
        "      <ul>{orders.map((order: any) => <li key={order.id}>{order.total}</li>)}</ul>\n"
        "    </main>\n"
        "  );\n"
        "}\n"
    ),
    "app/orders/[orderId]/page.tsx": (
        "export default async function OrderPage({ params }: { params: { orderId: string } }) {\n"
        "  const order = await fetch(`/api/orders/${params.orderId}`).then((response) => response.json());\n"
        "  return <p>{order.total}</p>;\n"
        "}\n"
    ),
    "app/products/page.tsx": (
        '"use client";\n'
        "\n"
        "export default function ProductsPage() {\n"
        "  return (\n"
        "    <form onSubmit={(event) => { event.preventDefault(); "
        'fetch("/api/reviews", { method: "POST", body: "{}" }); }}>\n'
        "      <button>Review</button>\n"
        "    </form>\n"
        "  );\n"
        "}\n"
    ),
    "db/schema.sql": (
        "CREATE TABLE customers (id serial PRIMARY KEY, email text NOT NULL);\n"
        "CREATE TABLE orders (\n"
        "  id serial PRIMARY KEY,\n"
        "  customer_id integer REFERENCES customers (id),\n"
        "  total numeric NOT NULL,\n"
        "  status text NOT NULL\n"
        ");\n"
    ),
}


def write_example_app(root: Path) -> None:
    """Write the example application under `root`."""
    for name, text in FILES.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
