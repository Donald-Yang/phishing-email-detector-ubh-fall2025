# No Phishing Allowed - a phishing email detector for Gmail 
Gmail Add-on that scans your email in real-time for suspicious attributes, helping you spot potential phishing attacks within an email.
(Created on November 9th, 2025 for UBHacking Fall 2025)

You will need to create your own Gmail Add-on in order to run these 2 files:
- Code.gs
- appsscript.json

1. First select and login to the Gmail account you want to add this Gmail Add-on to. 
2. Then navigate to Google's Apps Script workspace https://script.google.com/home (as of November 9th, 2025)
3. Then create your own project in Google's Apps Script and give it your desired title
4. In the project settings of your newly created project and select the box 'Show "appsscript.json" manifest file in editor'
5. Now you will see 2 files,
   - Code.gs
   - appsscript.json
6. Replace the code in both files with the respective files that I have provided in the repo
7. Save the files and select getContextualAddOn as the function to run
8. Click "Deploy"
9. Click "Test deployments", where a window will pop up saying "Test deployments"
10. You will then be able to select a type, which you will select "Google Workspace Add on"
11. You will then be able to see "Applications(s): Gmail", where you will install this 
12. Click "Done" 
13. Navigate to your Gmail, where on the right of the screen, you will see a new icon, which should say the title you gave it 
14. When the icon is clicked on, it will prompt you to give it permissions, which you will give or else the program will not work as intended
13. Finally, you will be able to check if your email has any signs of a phishing attack by clicking on Add-on, for which every email you are suspicious of

# ENJOY!!!!! 