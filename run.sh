#!/bin/bash
dropdb --if-exists rls && createdb rls
dropuser --if-exists api && createuser api
psql -U postgres -d rls -f rls_system.sql
psql -U postgres -d rls -f seed.sql
