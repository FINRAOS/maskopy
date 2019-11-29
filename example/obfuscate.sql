CREATE EXTENSION pgcrypto;
DO
LANGUAGE plpgsql $$
DECLARE
   v_salt VARCHAR;

BEGIN
select gen_salt('bf') into v_salt;

UPDATE org.emply set ACCT_NB = ('x'||encode(digest(ACCT_NB||v_salt,'sha256'),'hex'))::bit(26)::int;

   RAISE INFO '%',0;
END
$$;
select * from org.emply