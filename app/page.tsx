'use client';

import { connectDB } from "@/lib/mongodb";

export default function Home() {
  const handleClick = async () => {
      await fetch("/api/test", {
          method: "POST"
      });
  }

  return (
    <div className="flex flex-col flex-1 items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex flex-1 w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
        <button className="bg-white mg-12 text-black py-2 px-4" onClick={() => handleClick()}>Probar insertar</button>
      </main>
    </div>
  );
}
