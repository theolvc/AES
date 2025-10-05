#!/bin/bash

# Vérifie que le programme et le fichier existent
if [ ! -x "./AES" ]; then
    echo "Erreur : './AES' n'est pas exécutable ou n'existe pas."
    exit 1
fi

if [ ! -f "alice.sage" ]; then
    echo "Erreur : 'alice.sage' n'existe pas dans le répertoire courant."
    exit 1
fi

PROGRAM="./AES"
FILE="alice.sage"
ITERATIONS=100
TOTAL_TIME=0

echo "Mesure du temps pour $ITERATIONS exécutions de '$PROGRAM $FILE'..."

# Boucle pour exécuter le programme 100 fois
for ((i=1; i<=$ITERATIONS; i++)); do
    # Mesure le temps réel (en secondes) pour cette itération
    TIME=$( { time "$PROGRAM" "$FILE" >/dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' )
    # Convertit le temps en secondes (format mm:ss.sss)
    TIME_S=$(echo "$TIME" | awk -F'm' '{print $1*60 + $2}' | awk -F's' '{print $1}'| tr ',' '.')
    TOTAL_TIME=$(echo "$TOTAL_TIME + $TIME_S" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"
