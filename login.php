<?php require_once('header.php'); ?>
//fetching row banner login
<?php
$statement = $pdo->prepare("SELECT * FROM tbl_settings WHERE id=1");
$statement->execute();
$result = $statement->fetchAll(PDO::FETCH_ASSOC);                            
foreach ($result as $row) {
    $banner_login = $row['banner_login'];
}
?>
//login form
<?php
if(isset($_POST['form1'])) {
        
    if(empty($_POST['cust_email']) || empty($_POST['cust_password'])) {
        $error_message .= 'Invalid email or password.<br>';
    } else {
        // Fix ##3: inadequate input sanitization
       $cust_email = filter_var(trim($_POST['cust_email']), FILTER_SANITIZE_EMAIL);
       $cust_password = $_POST['cust_password'];

        $statement = $pdo->prepare("SELECT * FROM tbl_customer WHERE cust_email=?");
        $statement->execute(array($cust_email));
        $total = $statement->rowCount();
        $result = $statement->fetchAll(PDO::FETCH_ASSOC);
        foreach($result as $row) {
            $cust_status = $row['cust_status'];
            $row_password = $row['cust_password'];
        }

        if($total==0) {
    // Fix ##2: Generic error message (prevents user enumeration)
    $error_message .= 'Invalid email or password.<br>';
} else {
    // Fix ##1: Secure password verification with bcrypt + migration
    $password_valid = false;
    
    // Check if password is bcrypt (starts with $2y$) or old MD5
    if (substr($row_password, 0, 4) === '$2y$') {
        // Verify bcrypt hash
        if (password_verify($cust_password, $row_password)) {
            $password_valid = true;
        }
    } else {
        // Old MD5 hash - verify and migrate to bcrypt
        if (md5($cust_password) === $row_password) {
            $password_valid = true;
            // Rehash to bcrypt for future logins
            $new_hash = password_hash($cust_password, PASSWORD_BCRYPT);
            $update_stmt = $pdo->prepare("UPDATE tbl_customer SET cust_password = ? WHERE cust_id = ?");
            $update_stmt->execute(array($new_hash, $row['cust_id']));
        }
    }
    
    if (!$password_valid) {
        // Fix ##2: Generic error message
        $error_message .= 'Invalid email or password.<br>';
    } else {
        if($cust_status == 0) {
            $error_message .= 'Invalid email or password.<br>';
        } else {
            // Fix ##5: Session regeneration + Fix #6: exit()
            session_regenerate_id(true);
            $_SESSION['customer'] = $row;
            header("location: ".BASE_URL."dashboard.php");
            exit(); // Critical- Stop script execution.
        }
    }
}    
    }
}
?>

<div class="page-banner" style="background-color:#444;background-image: url(assets/uploads/<?php echo $banner_login; ?>);">
    <div class="inner">
        <h1><?php echo LANG_VALUE_10; ?></h1>
    </div>
</div>

<div class="page">
    <div class="container">
        <div class="row">
            <div class="col-md-12">
                <div class="user-content">

                    
                    <form action="" method="post">
                        <?php $csrf->echoInputField(); ?>                  
                        <div class="row">
                            <div class="col-md-4"></div>
                            <div class="col-md-4">
                                <?php
                               //##4 fixed cross site scripting(XSS)in success and error messages
                                if($error_message != '') {
                                  echo "<div class='error' style='padding: 10px;background:#f1f1f1;margin-bottom:20px;'>".htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8')."</div>";
                                }
                                if($success_message != '') {
                                  echo "<div class='success' style='padding: 10px;background:#f1f1f1;margin-bottom:20px;'>".htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8')."</div>";
                                }

                                ?>
                                <div class="form-group">
                                    <label for=""><?php echo LANG_VALUE_94; ?> *</label>
                                    <input type="email" class="form-control" name="cust_email">
                                </div>
                                <div class="form-group">
                                    <label for=""><?php echo LANG_VALUE_96; ?> *</label>
                                    <input type="password" class="form-control" name="cust_password">
                                </div>
                                <div class="form-group">
                                    <label for=""></label>
                                    <input type="submit" class="btn btn-primary" value="<?php echo LANG_VALUE_4; ?>" name="form1">
                                </div>
                                <a href="forget-password.php" style="color:#e4144d;"><?php echo LANG_VALUE_97; ?></a>
                            </div>
                        </div>                        
                    </form>
                      <!-- Google OAuth Login Button -->
                    <div style="text-align:center; margin: 30px 0; padding: 20px; border-top: 2px solid #f1f1f1;">
                        <p style="color: #666; margin-bottom: 15px; font-weight: bold;">OR</p>
                        <a href="google-config.php" style="display:inline-flex; align-items:center; background:#4285F4; color:white; padding:12px 24px; text-decoration:none; border-radius:5px; font-weight:bold; font-size:16px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);">
                        <svg width="20" height="20" viewBox="0 0 20 20" style="margin-right:10px;" xmlns="http://www.w3.org/2000/svg">
                               <path d="M18.1713 8.36791H17.5001V8.33325H10.0001V11.6666H14.7096C14.0225 13.607 12.1763 14.9999 10.0001 14.9999C7.23882 14.9999 5.00007 12.7612 5.00007 9.99992C5.00007 7.23867 7.23882 4.99992 10.0001 4.99992C11.2771 4.99992 12.4371 5.48033 13.3225 6.26575L15.6775 3.91075C14.1854 2.52158 12.1925 1.66658 10.0001 1.66658C5.39799 1.66658 1.66675 5.39783 1.66675 9.99992C1.66675 14.602 5.39799 18.3333 10.0001 18.3333C14.6021 18.3333 18.3334 14.602 18.3334 9.99992C18.3334 9.44117 18.2763 8.89575 18.1713 8.36791Z" fill="white"/>
                        </svg>
                             Login with Google
                        </a>
                    </div>
                </div>                
            </div>
        </div>
    </div>
</div>

<?php require_once('footer.php'); ?>