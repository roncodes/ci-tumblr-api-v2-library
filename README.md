<h1>Tumblr v2 OAuth API Library for CodeIgniter</h1>
<p>This is a work in progress currently, more api methods to be created as I go</p>

<h2>How to use</h2>
<pre>
$this->load->library('Tumblr');
$blog_info = $this->tumblr->blog_info();
// Blog info returned in object
echo $blog_info->title; // echo blog title
</pre>