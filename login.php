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
                </div>                
            </div>
        </div>
    </div>
</div>

<?php require_once('footer.php'); ?>