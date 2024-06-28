import turtle
import time  # Importer le module time pour les pauses

def dessiner_lettre_par_lettre(prenom):
    # Paramètres de la tortue
    turtle.speed(3)  # Vitesse la plus lente avec animation
    turtle.penup()  # Ne pas dessiner lors du déplacement initial

    # Position initiale
    turtle.goto(-100, 0)  # Déplacer la tortue au point de départ

    for lettre in prenom:
        turtle.pendown()  # Commencer à dessiner
        turtle.write(lettre, font=("Arial", 24, "bold"))  # Écrire une lettre
        turtle.penup()  # Ne pas dessiner en se déplaçant à la prochaine position de lettre
        turtle.forward(30)  # Déplacer la tortue à droite pour la prochaine lettre

    turtle.hideturtle()  # Cacher la tortue après le dessin
    turtle.done()  # Terminer le dessin

# Définir le prénom à dessiner
prenom = "coucou"
dessiner_lettre_par_lettre(prenom)
