create table testkit_pastes (
	id text primary key,
	title text not null,
	body text not null,
	syntax text not null,
	created_at timestamptz not null
);

create index testkit_pastes_created_at_id_idx
	on testkit_pastes (created_at desc, id asc);
