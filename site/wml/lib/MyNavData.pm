package MyNavData;

use strict;
use warnings;

use MyManageNews;

my $hosts =
{
    'main' =>
    {
        'base_url' => "http://gringotts.berlios.de/",
    },
};

my $news_manager = get_news_manager();

sub get_news_category
{
    my $items = $news_manager->get_navmenu_items('num_items' => 5);
    if (@$items)
    {
        return
        {
            'text' => "News",
            'url' => "news/",
            'subs' =>
            [
                @$items,
            ],
        },
    }
    else
    {
        return ();
    }
}

my $tree_contents =
{
    'host' => "main",
    'text' => "My Site",
    'title' => "My Site",
    'subs' =>
    [
        {
            'text' => "Home",
            'url' => "",
        },
        {
            'text' => "About",
            'url' => "about/",
        },
        get_news_category(),
        {
            'text' => "Links",
            'url' => "links.html",
        },
    ],
};

sub get_params
{
    return
        (
            'hosts' => $hosts,
            'tree_contents' => $tree_contents,
        );
}

1;
