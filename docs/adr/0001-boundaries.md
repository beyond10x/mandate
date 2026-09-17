# Standalone planes and typed boundaries

Status: accepted foundation decision under the supplied implementation plan.

Keep the original fourteen library crates and four deployments. Domain types contain no HTTP/database dependencies; resource services own business state. Mandate is standalone; no Identity migration.

Sources: original design §§2, 23–25, 40–42; addendum §§2–19. Open runtime choices remain in `../architecture/unmapped.md`.
