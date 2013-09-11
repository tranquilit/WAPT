import win32com.client
updateSession = win32com.client.Dispatch("Microsoft.Update.Session")
updateSearcher = updateSession.CreateupdateSearcher()
searchResult = updateSearcher.Search("IsInstalled=0 and Type='Software'")

print "\n".join([ update.Title for update in searchResult.Updates if update.MsrcSeverity == 'Critical'])
