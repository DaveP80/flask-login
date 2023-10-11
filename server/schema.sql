-- Create table in DATABASE FIRST. on each successful addition of new user to users table, new log is made in auth_users table
create table auth_users (user_id integer not null unique, user_email text not null unique, is_auth Boolean default false);

CREATE OR REPLACE FUNCTION insert_auth_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO auth_users (user_id, user_email, is_auth)
    VALUES (NEW.id, NEW.email, false);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_insert_trigger
AFTER INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION insert_auth_user();

-- images table
create table images (
    img_id serial PRIMARY KEY, id int not null, img_path text not null
);

ALTER TABLE images
ADD CONSTRAINT unique_id_img_path UNIQUE (id, img_path);

