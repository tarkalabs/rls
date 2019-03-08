create extension pgcrypto;

create schema auth;

create table auth.users (
  id serial primary key,
  username text not null unique,
  password text not null
);

create table auth.sessions(
  id serial primary key,
  user_id int not null references auth.users (id),
  token uuid not null default gen_random_uuid() unique);

create function auth.getauth(out token uuid) as $$
  begin
    select nullif(current_setting('auth.auth_token'), '') into token;
  exception when undefined_object then
  end;
$$ language plpgsql stable;

create function auth.setauth(token text) returns uuid as $$
  begin
    perform set_config('auth.auth_token', token, false);
    return auth.getauth();
  end;
$$ language plpgsql;

create function auth.token2user(_token text, out _user_id int) as $$
  begin
    select user_id from auth.sessions where token = _token::uuid into _user_id;
    if _user_id is null then
      raise 'AUTH_TOKEN_INVALID:NOEXIST';
    end if;
  end;
$$ language plpgsql security definer;

create function auth.current_user() returns int as $$
  declare
    token uuid;
  begin
    select auth.getauth() into token;
    return case
    when token is null
      then null
      else auth.token2user(token::text)
    end;
  end;
$$ language plpgsql stable;

create function auth.hashpass(password text, salt text default gen_salt('bf', 8)) 
  returns text as 'select crypt(password, salt)' language sql;

create function auth.login(_username text, _password text, out _token uuid) as $$
  declare
    _user auth.users;
  begin
    select * from auth.users where username = _username into _user;
    if _user is null or auth.hashpass(_password, _user.password) != _user.password then
      raise 'INVALID LOGIN';
    else
      insert into auth.sessions (user_id) values (_user.id) returning token into _token;
      perform auth.setauth(_token::text);
    end if;
  end;
$$ language plpgsql security definer;

create function auth.login(inout _token uuid) as $$
  begin
    perform auth.setauth(null);
    perform auth.token2user(_token); -- validate token
    perform auth.setauth(_token::text);
  end;
$$ language plpgsql security definer;

create function auth.logout(_token text default auth.getauth()) returns void as $$
  begin
    begin
      delete from auth.session where token=_token::uuid;
    exception when others then
    end;
    perform auth.setauth(null);
  end;
$$ language plpgsql security definer;

alter table auth.users enable row level security;

grant usage on schema auth to api;
grant select on auth.users to api;
create policy own_user on auth.users for select to api using (id = auth.current_user());

