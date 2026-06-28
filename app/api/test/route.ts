import { connectDB } from "@/lib/mongodb";
import { NextResponse } from "next/server";

export async function GET() {
  const db = await connectDB();

  const collections = await db.listCollections().toArray();

  return NextResponse.json(collections);
}

export async function POST() {
    const db = await connectDB();

    await db.collection("pruebaDeploy").insertOne({
        hola: "Este se hizo desde el deploy",
        fecha: new Date()
    });

    return NextResponse.json({
        ok: true
    });
}