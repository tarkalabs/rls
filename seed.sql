insert into auth.users(username, password) values ('appuser1', auth.hashpass('password')), ('appuser2', auth.hashpass('password'));
