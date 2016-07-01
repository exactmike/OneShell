  $forest = Get-ADForest                                                                                                                                              
  $schemalocation = "CN=Schema,$($forest.PartitionsContainer.split(',',2)[1])"                                                                                     
  $attributes = Get-ADObject -SearchBase $schemalocation -filter {ObjectClass -eq 'AttributeSchema'} -Properties *
  $objecttypes = Get-ADObject -SearchBase $schemalocation -filter {ObjectClass -eq 'classSchema' -and Name -eq 'User'} -Properties *