<?php

declare(strict_types=1);

use PhpCsFixer\Fixer\Comment\HeaderCommentFixer;
use PhpCsFixer\Fixer\ControlStructure\TrailingCommaInMultilineFixer;
use PhpCsFixer\Fixer\PhpUnit\PhpUnitExpectationFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;

return static function (ECSConfig $ecsConfig): void {
    $ecsConfig->sets([__DIR__.'/vendor/contao/easy-coding-standard/config/contao.php']);

    $ecsConfig->ruleWithConfiguration(HeaderCommentFixer::class, [
      'header' => ""
    ]);

    if (PHP_VERSION_ID < 80000) {
        $ecsConfig->ruleWithConfiguration(TrailingCommaInMultilineFixer::class, ['elements' => ['arrays'], 'after_heredoc' => true]);
        $ecsConfig->skip([PhpUnitExpectationFixer::class]);
    }

};
