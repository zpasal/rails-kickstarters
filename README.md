# rails-kickstarters


Set of Rails Application Templates to kicstart rails 6 applications:

* simple - Simple application with users, bootstrap, login, logout


## Simple

This is the simplest template, containing:
* Bootstrap 4 setup
* User model
* Session management (login / logout [no signup])
* seed.rb contains first user

Usage:

`rails new my-project -m https://raw.githubusercontent.com/zpasal/rails-kickstarters/main/simple.rb`

*NOTE: rails generator will ask you to overwrite couple of default files, please answer first question with `a` (all) 
and second with `n` (we do not want to overwrite our environment.js file from template)*

