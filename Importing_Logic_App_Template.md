How to import an existing Logic App template
1. Visit https://portal.azure.com and then go to the Logic App
2. Open any existing Logic App and navigate to Export template in Automation
![image](https://github.com/vrajsoniMS/m365-compliance-connector-sample-scripts/assets/112610093/2dedba28-d9ab-4938-bc87-fef0708348a3)

3. Click on Deploy
   ![image](https://github.com/vrajsoniMS/m365-compliance-connector-sample-scripts/assets/112610093/1750fb6e-0d16-40ca-a80f-b0eaff9a8a39)

4. Click Edit template
   ![image](https://github.com/vrajsoniMS/m365-compliance-connector-sample-scripts/assets/112610093/def7267f-add0-41d5-aab5-7df98aab6fd4)

5. Replace the contents of the template with the custom template provided in this [BYOD_Logic_App_Template](https://github.com/microsoft/m365-compliance-connector-sample-scripts/blob/main/BYOD%20Logic%20App%20Template.zip).
6. Update the template with relevant information (ex. Name, subscription, resource group etc.) and click Save
 ![image](https://github.com/vrajsoniMS/m365-compliance-connector-sample-scripts/assets/112610093/9c41a971-bf84-4e59-96ea-6f6c261ad5af)

7. Click on Review and Create and again, click on Create to create the logic app.
8. Navigate to newly created logic app, review the steps in Logic Apps Designer, test by clicking Run Trigger and Run.
9. After running successfully, Save and Enable the logic app.
