alter table testkit_pastes
	add column owner_principal_id text not null default '';

create index testkit_pastes_owner_principal_id_idx
	on testkit_pastes (owner_principal_id);
