file(SHA256 "${fixture}" digest)
file(WRITE "${output}" "#define XSQL_FIXTURE_SHA256 \"${digest}\"\n")
