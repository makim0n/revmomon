<html>
<head>
    <title>Ping, ping everywhere!</title>
    <meta chargset="utf-8" />
    <style>
    html {
        height: 100%;
    }
    body {
        background: linear-gradient(#e66465, #9198e5);
        height: 100%;
        margin: 0;
        background-repeat: no-repeat;
        background-attachment: fixed;
        text-align: center;
    }
    input {
        margin-top: 100px;
        width: 50%;
    }
    </style>
</head>
<body>
    <form method="POST" action="/index.php">
        <input type="text" name="cli_ip" placeholder="Ping your IP address" />
    </form>
    <pre>
    <?php
        if(isset($_POST['cli_ip'])) {
            if(exec('ping -c 3 '.$_POST['cli_ip'])) {
                echo "Host is up! :D";
            }
            else {
                echo "Host is down! :(";
            }
        } 
    ?>
    </pre>
</body>
</html>