package rag.policy
deny[msg] { input.doc; not input.doc.meta.signed_token; msg = sprintf("document %v is unsigned", [input.doc.id]) }
