CREATE TABLE notes (
    id bigint GENERATED ALWAYS AS IDENTITY,
    body text NOT NULL,
    CONSTRAINT notes_pkey PRIMARY KEY (id)
);
