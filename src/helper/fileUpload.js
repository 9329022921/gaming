/**require multer lib with the help we upload images */
const multer  = require('multer')

class Upload{
     upload=multer({
        storage:multer.diskStorage({
            /**define path where our image uploaded locally */
            destination:function(req,file,cb)
            {
                cb(null,'./upload')
            },
            /**describe unique image name  */
            filename :function(req,file,cb)
            {
                cb(null,file.fieldname+'-'+Date.now()+'.jpg')
            }
        })
    }).single('upload')
}

module.exports=new Upload()