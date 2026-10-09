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

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode ECB :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -d cipher.txt >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode ECB (Déchiffrement):"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -c data/IV.txt "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode CBC :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -c data/IV.txt -d cipher.txt >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode CBC (Déchiffrement):"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -f data/IV.txt "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode CFB :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -f data/IV.txt -d cipher.txt >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode CFB (Déchiffrement):"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -o data/IV.txt "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode OFB :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -o data/IV.txt -d cipher.txt >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode OFB (Déchiffrement):"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -g data/GCMIV.txt "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode GCM :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -g data/GMCIV.txt -d cipher.txt >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode GCM (Déchiffrement):"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"

TOTAL_TIME=0

for ((i=1; i<=$ITERATIONS; i++)); do
    # Enregistre le temps de début (secondes.nanosecondes)
    start=$(date +%s.%N)

    # Exécute le programme
    "$PROGRAM" -w "$FILE" >/dev/null 2>&1

    # Enregistre le temps de fin
    end=$(date +%s.%N)

    # Calcule la durée de l'itération et l'ajoute au total
    duration=$(echo "$end - $start" | bc)
    TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
done

# Calcule le temps moyen
AVERAGE_TIME=$(echo "scale=3; $TOTAL_TIME / $ITERATIONS" | bc)

echo "Mode WBC :"
echo "Temps total : $TOTAL_TIME secondes"
echo "Temps moyen par exécution : $AVERAGE_TIME secondes"
