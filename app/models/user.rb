class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable

  validates :email, :role, presence: true
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable


  def role?(r)
    role.include? r.to_s
  end

  def manager?
    return true if role == 'manager'
  end

  def audience?
    return true if role == 'audience'
  end
end
