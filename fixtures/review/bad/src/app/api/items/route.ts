import { createSupabaseServerClient } from "@/lib/supabase/server";

// PLANTED FAILURE. Do not fix this file — fixtures/ exists to be wrong.
//
// The reviewer must post an Important finding on the `.select("*")` line below.
export async function GET() {
  const supabase = await createSupabaseServerClient();

  // The planted defect: no org scope. Row level security is the only thing standing between
  // this and every row in the table, and the handler asserts nothing about the caller.
  const { data, error } = await supabase.from("items").select("*");

  if (error) {
    // Second planted defect, deliberately quieter: the caller's email lands in the log.
    console.error("items query failed for", data, error.message);
    return new Response("error", { status: 500 });
  }
  return Response.json(data);
}
