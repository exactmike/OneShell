  $forest = Get-ADForest                                                                                                                                              
  $schemalocation = "CN=Schema,$($forest.PartitionsContainer.split(',',2)[1])"                                                                                     
  $attributes = Get-ADObject -SearchBase $schemalocation -filter {ObjectClass -eq 'AttributeSchema'} -Properties *
  $objecttypes = Get-ADObject -SearchBase $schemalocation -filter {ObjectClass -eq 'classSchema' -and Name -eq 'User'} -Properties *
  http://blog.enowsoftware.com/solutions-engine/bid/185867/Powershell-Upping-your-Parameter-Validation-Game-with-Dynamic-Parameters-Part-II