export const PAYMENTS_API = "https://api.payments.example.com/v1";

export async function charge(token: string): Promise<void> {
  await fetch(`${PAYMENTS_API}/charge`, {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}
