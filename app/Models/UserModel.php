<?php

namespace App\Models;

use CodeIgniter\Model;
use PhpParser\Node\Expr\FuncCall;

class UserModel extends Model
{
    protected $db;

    public function __construct()
    {
        $this->db = \Config\Database::connect();
    }

    protected function sanitizing(array $array): array
    {
        return array_map(function ($post) {
            return filter_var($post, FILTER_SANITIZE_STRING);
        }, $array);
    }

    public function getUserDetails(array $post): array
    {
        $sanitizedPost = $this->sanitizing($post);
        $getUserDetailsQuery = "SELECT user_id, first_name, last_name, email, password, salt, user_level FROM tbl_users WHERE email = ? LIMIT 1;";
        $result = $this->db->query($getUserDetailsQuery, [$sanitizedPost['email']]);
        $user = $result->getRow();
        if (!$user) {
            return [];
        }
        $encrypted_password = md5($post['password'].''.$user->salt);
        if ($encrypted_password == $user->password) {
            return ['user_id' => $user->user_id, 'first_name' => $user->first_name, 'last_name' => $user->last_name, 'email' => $user->email, 'user_level' => $user->user_level];
        } else {
            return [];
        }
    }
    
    public function checkUserEmail(string $email): int
    {
        $email = filter_var($email, FILTER_SANITIZE_STRING, FILTER_SANITIZE_EMAIL);
        $checkEmailQuery = "SELECT COUNT(*) as emailCount FROM tbl_users WHERE email = ?";
        $result = $this->db->query($checkEmailQuery, [$email]);
        $row = $result->getRowArray();
        return $row['emailCount'];
    }

    protected function checkIfNoUser(): bool
    {
        $checkUserQuery = "SELECT COUNT(*) as countUser FROM tbl_users";
        $result = $this->db->query($checkUserQuery);
        $row = $result->getRowArray();
        return $row['countUser'] ? false : true;
    }

    public function selectUser(int $id): array
    {
        $checkUserQuery = "SELECT user_id, first_name, last_name, email, user_level, description, created_at FROM tbl_users WHERE user_id = ? LIMIT 1";
        $result = $this->db->query($checkUserQuery, [filter_var($id, FILTER_SANITIZE_NUMBER_INT)]);
        if ($result->getRowArray()) {
            return $result->getRowArray();
        } else {
            return [];
        }
    }

    public function updateUser(array $post): bool
    {
        $sanitizedPost = $this->sanitizing($post);
        if (isset($post['user_level'])) {
            $sanitizedPost['user_level'] = @$sanitizedPost['user_level'] == "Admin" ?  9 : 1;
        }
        $isAdminUserUpdateQuery = @$sanitizedPost['user_level'] ? "email = ?, first_name = ?, last_name = ?, user_level = ?" : "email = ?, first_name = ?, last_name = ?";
        $updateQuery = @$sanitizedPost['description'] ? "description = ?" : $isAdminUserUpdateQuery;
        
        $updateUserQuery = "UPDATE tbl_users SET {$updateQuery} WHERE user_id = ?;";
        $this->db->query($updateUserQuery, [...array_values($sanitizedPost)]);// spreading all the values from the sanitizedPost
        $result = $this->db->affectedRows();
        if ($result) {
            return true;
        } else {
            return false;
        }
    }

    public function updateUserPassword(array $post): bool
    {
        unset($post['confirm_password']); // remove confirm password from data array
        $sanitizedPost = $this->sanitizing($post);
        $salt = bin2hex(openssl_random_pseudo_bytes(22)); // hashing for password
        $encrypted_password = md5($sanitizedPost['password']. '' .$salt); // encrypted password using the hashing salt
        $updateUserPasswordQuery = "UPDATE tbl_users SET password = ?, salt = ? WHERE user_id = ?;";
        $this->db->query($updateUserPasswordQuery, [$encrypted_password, $salt, $sanitizedPost['user_id']]);
        $result = $this->db->affectedRows();
        if ($result) {
            return true;
        } else {
            return false;
        }
    }


    public function deleteUser(array $post): bool
    {
        $sanitizedPost = $this->sanitizing($post); 
        $deleteMessageQuery = "DELETE FROM tbl_users WHERE user_id = ?;";
        $this->db->query($deleteMessageQuery, [...array_values($sanitizedPost)]);// spreading all the values from the sanitizedPost
        $result = $this->db->affectedRows();
        return $result ? true : false;
    }

    public function createUser(array $post): int
    {
        unset($post['confirm_password']); // remove confirm password from data array
        unset($post['create_new_user']); // remove create_new_user from data array
        /**
         * Map all data in the array and return the values that are being sanitized
         */
        $sanitizedPost = $this->sanitizing($post);
        
        $salt = bin2hex(openssl_random_pseudo_bytes(22)); // hashing for password
        $encrypted_password = md5($sanitizedPost['password']. '' .$salt); // encrypted password using the hashing salt

        $sanitizedPost['password'] = $encrypted_password;
        $sanitizedPost['salt'] = $salt;
        $sanitizedPost['user_level'] = $this->checkIfNoUser() ? 9 : 0; // it will check if there any user in the table, if theres none the first user that will register will be admin

        $insertUserQuery = "INSERT INTO tbl_users(email, first_name, last_name, password, salt, user_level) VALUES(?,?,?,?,?,?);";
        $this->db->query($insertUserQuery, [...array_values($sanitizedPost)]);// spreading all the values from the sanitizedPost
        $result = $this->db->affectedRows();
        $lastId = $this->db->insertID();
        if ($result) {
            return $lastId;
        } else {
            return 0;
        }
    }
}
