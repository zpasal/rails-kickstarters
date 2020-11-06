# template.rb
gem     "bcrypt", "~> 3.1.7"

run     "yarn add bootstrap jquery popper.js"

route   "root to: 'home#index'"
route   "resources :sessions, only: [:new, :create, :destroy]"

generate :resource, "user", "email:string", "firstname:string", "lastname:string", "role:integer", "password_digest:string", "auth_key:string"


###################################################################
#
#        CONTROLLERS
#

file "app/controllers/application_controller.rb", <<-CODE
class ApplicationController < ActionController::Base
  add_flash_types :info, :error, :warning

  helper_method :current_user, :is_admin?

  def current_user
    @current_user ||= User.find_by(auth_key: session[:user_id]) if session[:user_id]
  end

  def authorize
    redirect_to login_path, alert: 'You must be logged in to access this page.' if current_user.nil?
  end

  def is_admin?
    current_user&.role == 'admin'
  end
end
CODE

file "app/controllers/sessions_controller.rb", <<-CODE
class SessionsController < ApplicationController
  def new
    redirect_to redirect_path if current_user
  end

  def create
    user = User.find_by(email: params[:email].downcase)

    if user && user.authenticate(params[:password])
      session[:user_id] = user.auth_key
      redirect_to redirect_path
    else
      redirect_to new_session_path, notice: 'Incorrect email or password, try again.'
    end
  end

  def redirect_path
    root_path
  end

  def destroy
    current_user.reset_auth_key if current_user
    session.delete(:user_id)
    redirect_to root_path
  end
end
CODE

file "app/controllers/home_controller.rb", <<-CODE
class HomeController < ApplicationController
  def index
  end
end
CODE


###################################################################
#
#        MODELS
#

file "app/models/user.rb", <<-CODE
class User < ApplicationRecord
  has_secure_password
  attribute :password_confirmation, :string
  enum role: ['admin', 'regular_user']  # extend for more role e.g. ['admin', 'manager', 'regular_user']

  validates :email, :role, presence: true
  validates :password, presence: { on: :create }, length: { within: 6..15, allow_blank: true }, confirmation: true
  validates :password_confirmation, :presence => true, if: :password_present
  validates :auth_key, uniqueness: true, allow_nil: true

  before_create :generate_auth_key, :prepare_email

  def reset_auth_key
    self.generate_auth_key
    self.save!
  end

  def generate_auth_key
    self.auth_key = loop do
      key = SecureRandom.urlsafe_base64
      break key unless User.exists?(auth_key: key)
    end
  end

  private

  def prepare_email
    email.strip!
    email.downcase!
  end

  def password_present
    password.present?
  end
end
CODE

###################################################################
#
#        VIEWS
#
file "app/views/layouts/application.html.erb", <<-CODE
<!DOCTYPE html>
<html>
  <head>
    <title>TITLE</title>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <%= csrf_meta_tags %>
    <%= csp_meta_tag %>

    <%= stylesheet_link_tag 'application', media: 'all', 'data-turbolinks-track': 'reload' %>
    <%= stylesheet_pack_tag 'application', media: 'all', 'data-turbolinks-track': 'reload' %>
    <%= javascript_pack_tag 'application', 'data-turbolinks-track': 'reload' %>
  </head>

  <body>
    <%= render 'layouts/navbar' %>
    <main role="main" class="container" style="margin-top:56px;">
      <%= render 'layouts/flash_messages' %>
      <%= yield %>
    </main>
  </body>
</html>
CODE

file "app/views/layouts/_navbar.html.erb", <<-CODE
<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
  <a class="navbar-brand" href="#">Navbar</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExampleDefault" aria-controls="navbarsExampleDefault" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarsExampleDefault">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/">Home</a>
      </li>
    </ul>
    <ul class="navbar-nav">
      <% if current_user.nil? %>
      <li class="nav-item">
        <%= link_to 'Login', new_session_path, class: 'nav-link' %>
      </li>
      <% elsif %>
      <li class="nav-item">
        <%= link_to 'Logout', session_path(0), class: 'nav-link', :method => :delete %>
      </li>
      <% end %>
    </ul>        
  </div>
</nav>
CODE

file "app/views/layouts/_flash_messages.html.erb", <<-CODE
<% unless flash.empty? %>
  <% flash.each do |name, msg| %>
    <div class="text-center alert alert-<%= name == "notice" ? "success" : "danger" %> alert-dismissable">
      <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
      <% msg = *msg %>
      <% msg.each do |item| %>
        <p>
          <%= item %>
        </p>
      <% end %>
    </div>
  <% end %>
<% end %>
CODE

file "app/views/sessions/new.html.erb", <<-CODE
<div class='container-fluid h-100'>
  <div class='row'>
    <div class='col-xs-12 col-sm-9 col-md-7 col-lg-5 mx-auto'>
      <div class='card card-signin my-5 login_box'>
        <div class='card-body text-center'>
          <div class='logo_img'>
            LOGO PLACEHOLDER
          </div>
          <div class='login_form'>
            <%= form_tag sessions_path, method: :post, id: 'login_form', class: 'form-signin' do %>
              <div class='form-group email_group'>
                <%= label_tag :email, 'Email', class: 'float-left email_label' %>
                <%= text_field_tag(:email, params[:email], class: 'form-control email_input', placeholder: 'email@email.com', required: true, autofocus: true) %>
              </div>
              <div class='form-group password_group'>
                <%= label_tag :password, 'Password', class: 'float-left password_label' %>
                <%= text_field_tag(:password, params[:password], class: 'form-control password_input', placeholder: raw("&bull; &bull; &bull; &bull; &bull;"), required: true, type: 'password') %>
              </div>
              <div class='login_button_frame'>
                <%= button_tag('Login', class: 'btn btn-lg btn-primary btn-block login_btn') %>
              </div>
            <% end %>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
CODE

file "app/views/home/index.html.erb", <<-CODE
<div class="content-wrapper">
  <div class="content-header">
    <div class="container-fluid">
      <div class="row mb-2">
        <div class="col-sm-6">
          <h1 class="m-0 text-dark">Početna</h1>
        </div>
      </div>
    </div>
  </div>

  <section class="content">
    <div class="container-fluid">
      <div class="row">
        <div class="col-lg-4 col-xs-6">
        </div>
        <div class="col-lg-4 col-xs-6">
        </div>
      </div>
    </div>
  </section>
</div>
CODE


file "db/seeds.rb", <<-CODE
def users
  [
    {
      email: 'admin@admin.com',
      firstname: 'Admin',
      lastname:'Admin',
      password: 'Admin1234!',
      password_confirmation: 'Admin1234!',
      auth_key: 'WKtKtyqR8QN8xyLDnm0UUA',
      role: 0
    }
  ]
end

users.each do |seed|
  User.where(email: seed[:email]).first_or_create do |user|
    user.email = seed[:email]
    user.firstname = seed[:firstname]
    user.lastname = seed[:lastname]
    user.password = seed[:password]
    user.password_confirmation = seed[:password_confirmation]
    user.role = seed[:role]
  end
end
CODE

file "config/webpack/environment.js", <<-CODE
const { environment } = require('@rails/webpacker')
 
const webpack = require('webpack')
environment.plugins.append('Provide',
  new webpack.ProvidePlugin({
    $: 'jquery',
    jQuery: 'jquery',
    Popper: ['popper.js', 'default']
  })
)
  
module.exports = environment
CODE

file "app/assets/stylesheets/application.css", <<-CODE
/*
  *= require bootstrap
  *= require_tree .
  *= require_self
*/
CODE

file "app/javascript/stylesheets/application.scss", <<-CODE
@import '~bootstrap/scss/bootstrap';
CODE


inject_into_file 'app/javascript/packs/application.js', :after => "require(\"channels\")" do
'''

import "bootstrap";
import "../stylesheets/application"
document.addEventListener("turbolinks:load", () => {
  $(\'[data-toggle="tooltip"]\').tooltip()
  $(\'[data-toggle="popover"]\').popover()
})
'''
end

rails_command "db:migrate"
rails_command "db:seed"
