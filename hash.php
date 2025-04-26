<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

// Démarrer une session pour la protection CSRF
session_start();

// Génération d'un token CSRF si absent
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Traitement du formulaire
$hashedPassword = '';
$hashInfo = [];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(400);
        exit('Erreur sécurité : jeton CSRF invalide.');
    }

    // Vérification des champs
    $password = $_POST['password'] ?? '';
    $algorithm = $_POST['algorithm'] ?? '';

    // Sécurisation des entrées
    $password = trim($password);

    // Choix de l'algorithme
    $algoMap = [
        'default'   => PASSWORD_DEFAULT,
        'bcrypt'    => PASSWORD_BCRYPT,
        'argon2i'   => PASSWORD_ARGON2I,
        'argon2id'  => PASSWORD_ARGON2ID,
    ];

    if (empty($password)) {
        $error = 'Veuillez entrer une chaîne à hasher.';
    } elseif (!isset($algoMap[$algorithm])) {
        $error = 'Méthode de hachage invalide.';
    } else {
        // Hachage sécurisé
        $hashedPassword = password_hash($password, $algoMap[$algorithm]);
        if ($hashedPassword !== false) {
            $hashInfo = password_get_info($hashedPassword);
        } else {
            $error = 'Erreur lors du hachage.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<!-- Ajout de Font Awesome pour l'icône -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">

<body>
    <!-- Icône de clé avec le compteur de mots de passe -->
    <div id="keyIcon">
        <i class="fas fa-key"></i>
        <div id="passwordCount">0</div>
    </div>

    <head>
        <meta charset="UTF-8">
        <title>Hashage sécurisé</title>
        <style>
        body {
            background: #f5f5f5;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            padding-top: 50px;
        }

        .container {
            background: #fff;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
            width: 600px;
        }

        h1 {
            margin-bottom: 20px;
            font-size: 2em;
        }

        input,
        select,
        button {
            padding: 10px;
            width: 100%;
            margin: 10px 0;
            font-size: 1em;
            border-radius: 8px;
            border: 1px solid #ccc;
        }

        .result {
            margin-top: 30px;
            background: #e8f5e9;
            padding: 20px;
            border-radius: 10px;
            word-break: break-all;
        }

        .error {
            color: red;
            font-weight: bold;
            margin-top: 20px;
        }

        /* Style de l'icône et du compteur */
        #keyIcon {
            font-size: 40px;
            color: #4CAF50;
            position: fixed;
            top: 20px;
            left: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        #passwordCount {
            font-size: 16px;
            margin-left: 10px;
            color: #333;
        }

        /* Compteur en rouge si il y a des entrées */
        #passwordCount.positive {
            color: #ff5722;
        }
        </style>
    </head>

    <body>

        <div class="container">
            <h1>Hashage de chaîne sécurisé</h1>

            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                <input type="text" name="password" placeholder="Entrez la chaîne à hasher" required>

                <select id="algorithm" name="algorithm" required>
                    <option value="default">Par défaut (recommandé)</option>
                    <option value="bcrypt">BCRYPT</option>
                    <option value="argon2i">Argon2i</option>
                    <option value="argon2id">Argon2id (le plus solide)</option>
                </select>

                <button type="submit">Hasher</button>
            </form>

            <?php if (!empty($error)): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if (!empty($hashedPassword)): ?>
            <div class="result">
                <strong>Chaîne originale :</strong><br>
                <code id="originalPassword"><?= htmlspecialchars($password) ?></code><br>
                <button onclick="copyText('originalPassword')" style="margin-top:8px;">Copier la chaîne</button>

                <hr style="margin:20px 0;">

                <strong>Mot de passe hashé :</strong><br>
                <code id="hashedPassword"><?= htmlspecialchars($hashedPassword) ?></code><br>
                <button onclick="copyText('hashedPassword')" style="margin-top:8px;">Copier le hash</button>

                <hr style="margin:20px 0;">

                <strong>Algorithme utilisé :</strong><br>
                <code><?= htmlspecialchars($hashInfo['algoName']) ?></code>

                <div id="copyMessage" style="color:green; margin-top:15px; display:none;">Copié !</div>
            </div>
            <?php endif; ?>
            <hr style="margin:20px 0;">

            <button onclick="addToFile()" style="background-color: #4CAF50; color: white; margin: 10px;">Ajouter au
                fichier</button>
            <button onclick="downloadFile()" style="background-color: #2196F3; color: white; margin: 10px;">Télécharger
                le fichier</button>
            <button id="clearSave">Effacer la sauvegarde</button>

            <div id="saveMessage" style="color:blue; margin-top:15px; display:none;">Ajouté à la sauvegarde !</div>


            <script>
            function copyHash() {
                const hashText = document.getElementById('hashedPassword').innerText;
                navigator.clipboard.writeText(hashText).then(function() {
                    const message = document.getElementById('copyMessage');
                    message.style.display = 'block';
                    setTimeout(() => {
                        message.style.display = 'none';
                    }, 1500);
                }, function(err) {
                    console.error('Erreur de copie : ', err);
                });
            }
            </script>
            <script>
            let savedEntries = [];

            // Chargement initial depuis le localStorage
            if (localStorage.getItem('savedEntries')) {
                savedEntries = JSON.parse(localStorage.getItem('savedEntries'));
                updatePasswordCountDisplay();
            }

            document.getElementById('clearSave').addEventListener('click', function() {
                if (confirm('Es-tu sûr de vouloir effacer toutes les entrées sauvegardées ?')) {
                    savedEntries = [];
                    localStorage.removeItem('savedEntries');
                    updatePasswordCountDisplay();
                    alert('Sauvegarde effacée.');
                }
            });


            function copyText(elementId) {
                const text = document.getElementById(elementId).innerText;
                navigator.clipboard.writeText(text).then(function() {
                    const message = document.getElementById('copyMessage');
                    message.style.display = 'block';
                    setTimeout(() => {
                        message.style.display = 'none';
                    }, 1500);
                }, function(err) {
                    console.error('Erreur de copie : ', err);
                });
            }

            function addToFile() {
                const original = document.getElementById('originalPassword').innerText;
                const hashed = document.getElementById('hashedPassword').innerText;
                const method = document.getElementById('algorithm').value;


                const entry = `Méthode : ${method}\nChaîne : ${original}\nHash : ${hashed}\n\n`;
                savedEntries.push(entry);

                // Mise à jour du localStorage
                localStorage.setItem('savedEntries', JSON.stringify(savedEntries));

                updatePasswordCountDisplay();

                const saveMessage = document.getElementById('saveMessage');
                saveMessage.style.display = 'block';
                setTimeout(() => {
                    saveMessage.style.display = 'none';
                }, 1500);
            }


            function downloadFile() {
                if (savedEntries.length === 0) {
                    alert('Aucune donnée à télécharger.');
                    return;
                }

                const blob = new Blob(savedEntries, {
                    type: 'text/plain'
                });
                const url = URL.createObjectURL(blob);

                const a = document.createElement('a');
                a.href = url;
                a.download = 'hashes_sauvegarde.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                URL.revokeObjectURL(url);
            }

            function updatePasswordCountDisplay() {
                const passwordCount = savedEntries.length;
                const countElement = document.getElementById('passwordCount');
                countElement.innerText = passwordCount;
                if (passwordCount > 0) {
                    countElement.classList.add('positive');
                } else {
                    countElement.classList.remove('positive');
                }
            }
            </script>
    </body>