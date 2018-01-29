-- Create a view that joins the Drupal users table with various field data 
-- tables.
-- 
-- As well as a username and a password, Moodle requires every profile to 
-- have an email address, first name and last name. If they don't exist when 
-- someone is authenticated then Moodle will send the user to the profile 
-- editing page.
-- 
-- In this example the resulting view has the username and email address from 
-- the users table, plus three custom fields:
--   field_first_name
--   field_last_name
--   field_city
-- 
-- User profile fields are created in admin/config/people/accounts/fields 
-- in Drupal. If you make first name and last name a required field then 
-- you can ensure they are always available to Moodle when someone is  
-- authenticated with CAS.
-- 

DROP VIEW IF EXISTS user_profiles;
CREATE VIEW user_profiles AS (
  SELECT      u.name AS name,
              u.mail AS mail,
              fn.field_first_name_value AS first_name,
              ln.field_last_name_value AS last_name,
              c.field_city_value AS city
  FROM        users u
  LEFT JOIN   field_data_field_first_name fn
    ON        u.uid = fn.entity_id
  LEFT JOIN   field_data_field_last_name ln
    ON        u.uid = ln.entity_id
  LEFT JOIN   field_data_field_city c
    ON        u.uid = c.entity_id
  WHERE       u.uid != 0
);
