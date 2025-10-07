AccessChk GUI — v1.4
=====================
• 'Aide' → explications et exemples pour le champ 'Principal'
• Suppose que accesschk.exe est dans le même dossier que le GUI
• 'Only folders' fiabilisé (détection de chemin même avec préfixes 'RW '), export filtré
• Barre de progression + compteur de lignes

Build EXE (optionnel) :
pyinstaller --onefile --noconsole --name AccessChkGUI accesschk_gui_tk.py
# (ne pas utiliser --add-binary ; place accesschk.exe manuellement à côté du .exe)

Conseils Principal :
- Laissez vide pour essai auto : Utilisateurs → Users → BUILTIN\Users → S-1-5-32-545
- Ou saisissez un groupe/compte : Users, Utilisateurs, BUILTIN\Users, DOMAINE\Groupe, etc.
- 'whoami /groups' pour lister vos groupes.
