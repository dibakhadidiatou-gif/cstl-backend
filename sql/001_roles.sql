-- Comptes et roles (technicien < admin < superadmin).
-- A executer une fois dans le SQL Editor de Supabase, AVANT de deployer le
-- code qui utilise la table users.

-- 1. Compteur de tentatives des codes de connexion (limite a 5 essais).
alter table admin_codes add column if not exists attempts int not null default 0;

-- 2. Table des comptes. Les adresses sont toujours stockees en minuscules.
create table if not exists users (
  email      text primary key check (email = lower(btrim(email))),
  role       text not null check (role in ('technicien', 'admin', 'superadmin')),
  created_by text,
  added_at   timestamptz not null default now()
);

-- Seul le backend (cle service_role, qui ignore RLS) doit lire ou ecrire
-- cette table : RLS active sans aucune policy bloque tout acces direct depuis
-- un navigateur avec la cle anon.
alter table users enable row level security;

-- 3. Reprise des administrateurs existants, en tant qu'admin.
insert into users (email, role, added_at)
select distinct on (lower(btrim(email))) lower(btrim(email)), 'admin', added_at
from admin_emails
order by lower(btrim(email)), added_at
on conflict (email) do nothing;

-- 4. Designer au moins un superadmin (remplacer l'adresse) — sans lui,
--    personne ne peut creer d'admin ni reinitialiser les donnees.
insert into users (email, role) values ('REMPLACER@exemple.com', 'superadmin')
on conflict (email) do update set role = 'superadmin';

-- 5. Une fois le nouveau code deploye et verifie, l'ancienne table peut
--    etre supprimee :
-- drop table admin_emails;
