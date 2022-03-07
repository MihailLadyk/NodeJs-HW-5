const express = require("express");
const contactsModel = require("../../models/contactsSchema");
const router = express.Router()

router.get('/', async (req, res, next) => {

  try{
    const contacts = await contactsModel.find();

    return res.json({
      status: 'success',
      code: 200,
      data: {
        contacts,
      }
    })
  } catch(error){
    next(error)

  }

});

router.get('/:contactId', async (req, res, next) => {
  const { contactId } = req.params;
  try{
    const contacts = await contactsModel.findById(contactId);

    console.log(contacts)
    res.json({ message: contacts })
  } catch(error){
    res.status(500).send({message: 'error'})
    console.log(error)
  }

})

router.post('/', async (req, res, next) => {

    try {
      const new_contact = await contactsModel.create(req.body);

      return res.json({
        status: 'success',
        code: 200,
        data: {
          new_contact,
        }
      })
    } catch (error) {
      console.log(error)
      res.status(500).json(error);
    }

})

router.delete('/:contactId', async (req, res, next) => {
  const { contactId } = req.params;
  try{
    const contact = await contactsModel.findByIdAndDelete(contactId)
    return res.json({
      status: 'contact deleted',
      code: 200,
      data: {
        contact,
      }
    })
  } catch(error){
    res.status(500).send({message: 'error'})
    console.log(error)
  }
})

router.put('/:contactId', async (req, res, next) => {
  const { contactId } = req.params;
  try{
    const updated_contact = await contactsModel.findByIdAndUpdate(contactId, req.body, {
      new: true
    })

    console.log(updated_contact)
    return res.json({
      status: 'success',
      code: 200,
      data: {
        updated_contact,
      }
    })
  } catch(error){
    res.status(500).send({message: 'error'})
    console.log(error)
  }
})

router.patch('/:contactId/favorite', async (req, res, next) => {
  const { contactId } = req.params;
  try{
    const contact = await contactsModel.findById(contactId);

    if(
      req.body.favorite === undefined ||
      typeof req.body.favourite !== 'boolean'
    ){
      return res.status(400).json({message: 'missing field favourite'})
    }
    
    console.log(contact)
    if(contact.favorite === false){
      contact.favorite = true
    } else {
      contact.favorite = false
    }

    await contact.save();

    return res.json({
      status: 'success',
      code: 200,
      data: {
        contact,
      }
    })

  
  } catch(error){
    res.status(500).send({message: 'error'})
    console.log(error)
  }

} )
module.exports = router
